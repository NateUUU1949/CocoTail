using Konscious.Security.Cryptography;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CocoTail
{
    public sealed class CocoTailDigest : IDisposable
    {
        private const int STATE_WIDTH_BITS = 1600;
        private const int STATE_WIDTH_BYTES = STATE_WIDTH_BITS / 8;
        private const int STATE_WIDTH_ULONGS = STATE_WIDTH_BYTES / 8;

        private readonly int _keccakCapacityBits = 1024;
        private readonly int _keccakRateBits;
        private readonly int _keccakRateBytes;

        private const int KECCAK_ROUNDS = 24;
        private static readonly ulong[] RoundConstants = new ulong[]
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private static readonly int[,] RotationOffsets = new int[5, 5]
        {
            { 0, 36, 3, 41, 18 }, { 1, 44, 10, 45, 2 }, { 62, 6, 43, 15, 61 },
            { 28, 55, 25, 21, 56 }, { 27, 20, 39, 8, 14 }
        };

        private const int BLOCK_SIZE_BYTES = 64;
        private const int SHA512_SIZE = 64;

        private readonly int _outputLengthBits;
        private readonly int _outputLengthBytes;
        private readonly int _memoryBlocks;
        private readonly int _timeCost;

        private bool _disposed;

        private readonly int _argonMemoryKb;
        private readonly int _argonIterations;
        private readonly int _argonParallelism;

        public CocoTailDigest(int outputLengthBits = 512, int memoryBlocks = 8192, int timeCost = 3,
                              int? argonMemoryKb = null, int argonIterations = 3, int argonParallelism = 1)
        {
            if (outputLengthBits % 8 != 0) throw new ArgumentException("Output must be multiple of 8.", nameof(outputLengthBits));
            if (memoryBlocks < 4) throw new ArgumentException("Memory blocks must be >= 4.", nameof(memoryBlocks));
            if (timeCost < 1) throw new ArgumentException("Time cost must be >= 1.", nameof(timeCost));
            if (argonIterations < 1) throw new ArgumentException("Argon iterations must be >= 1.", nameof(argonIterations));
            if (argonParallelism < 1) throw new ArgumentException("Argon parallelism must be >= 1.", nameof(argonParallelism));

            _outputLengthBits = outputLengthBits;
            _outputLengthBytes = _outputLengthBits / 8;
            _memoryBlocks = memoryBlocks;
            _timeCost = timeCost;

            _keccakRateBits = STATE_WIDTH_BITS - _keccakCapacityBits;
            _keccakRateBytes = _keccakRateBits / 8;

            int mappedKb = checked((_memoryBlocks * BLOCK_SIZE_BYTES) / 1024);
            int minKb = 8 * 1024;
            int maxKb = 256 * 1024;
            int chosen = Math.Clamp(mappedKb, minKb, maxKb);

            _argonMemoryKb = argonMemoryKb ?? chosen;
            _argonIterations = argonIterations;
            _argonParallelism = argonParallelism;
        }

        public byte[] ComputeHash(byte[] input, byte[] salt)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(CocoTailDigest));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (salt == null || salt.Length < 16) throw new ArgumentException("Salt mandatory (min 16 bytes).", nameof(salt));

            int totalMemoryBytes = checked(_memoryBlocks * BLOCK_SIZE_BYTES);
            byte[] bigMemory = null;
            byte[] combined = null;
            byte[] keccakOut = null;

            try
            {
                bigMemory = ArrayPool<byte>.Shared.Rent(totalMemoryBytes);
                combined = ArrayPool<byte>.Shared.Rent(BLOCK_SIZE_BYTES * 2);
                keccakOut = ArrayPool<byte>.Shared.Rent(BLOCK_SIZE_BYTES);

                Span<byte> BlockSpan(int idx) => bigMemory.AsSpan(idx * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES);

                byte[] prehashInput = BuildPrehashInput(input, salt);
                InternalSpongeHash(prehashInput, BlockSpan(0));
                CryptographicOperations.ZeroMemory(prehashInput);

                SHA512.HashData(salt, BlockSpan(1));

                for (int i = 2; i < _memoryBlocks; i++)
                {
                    BlockSpan(i - 1).CopyTo(combined.AsSpan(0, BLOCK_SIZE_BYTES));
                    BlockSpan(i - 2).CopyTo(combined.AsSpan(BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES));

                    InternalSpongeHash(combined, keccakOut.AsSpan(0, BLOCK_SIZE_BYTES));
                    byte[] shaInput = BuildTweak(keccakOut, salt, i, 0);
                    SHA512.HashData(shaInput, BlockSpan(i));

                    CryptographicOperations.ZeroMemory(shaInput);
                }

                for (int t = 0; t < _timeCost; t++)
                {
                    bool isDataIndependentPass = (t == 0);
                    for (int i = 0; i < _memoryBlocks; i++)
                    {
                        int prevIndex = (i == 0) ? _memoryBlocks - 1 : i - 1;
                        ReadOnlySpan<byte> prevBlock = BlockSpan(prevIndex);

                        int j = isDataIndependentPass
                            ? GetIndependentIndex(i, salt, t, (i == 0) ? 0 : i)
                            : GetDependentIndex(prevBlock, (i == 0) ? 0 : i);

                        prevBlock.CopyTo(combined.AsSpan(0, BLOCK_SIZE_BYTES));
                        BlockSpan(j).CopyTo(combined.AsSpan(BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES));

                        InternalSpongeHash(combined, keccakOut.AsSpan(0, BLOCK_SIZE_BYTES));
                        byte[] shaInput = BuildTweak(keccakOut, salt, i, t + 1);
                        SHA512.HashData(shaInput, BlockSpan(i));

                        CryptographicOperations.ZeroMemory(shaInput);
                    }
                }

                Span<byte> finalBlockSpan = BlockSpan(_memoryBlocks - 1);
                byte[] intermediate = new byte[_outputLengthBytes];
                InternalSpongeHash(finalBlockSpan, intermediate.AsSpan());
                byte[] finalOutput = new byte[_outputLengthBytes];

                try
                {
                    using var argon = new Argon2id(intermediate)
                    {
                        MemorySize = _argonMemoryKb,
                        Iterations = _argonIterations,
                        DegreeOfParallelism = _argonParallelism
                    };

                    argon.Salt = salt;
                    byte[] derived = argon.GetBytes(_outputLengthBytes);

                    Buffer.BlockCopy(derived, 0, finalOutput, 0, _outputLengthBytes);
                    CryptographicOperations.ZeroMemory(derived);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(intermediate);
                }

                return finalOutput;
            }
            finally
            {
                if (bigMemory != null) ArrayPool<byte>.Shared.Return(bigMemory, clearArray: true);
                if (combined != null) ArrayPool<byte>.Shared.Return(combined, clearArray: true);
                if (keccakOut != null) ArrayPool<byte>.Shared.Return(keccakOut, clearArray: true);
            }
        }

        private byte[] BuildPrehashInput(byte[] input, byte[] salt)
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);
            writer.Write((int)input.Length);
            writer.Write(input);
            writer.Write((int)salt.Length);
            writer.Write(salt);
            writer.Write((int)_outputLengthBits);
            writer.Write((int)_memoryBlocks);
            writer.Write((int)_timeCost);
            writer.Write((int)_keccakCapacityBits);
            return ms.ToArray();
        }

        private byte[] BuildTweak(ReadOnlySpan<byte> mainData, byte[] salt, int i, int t)
        {
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);
            writer.Write((int)mainData.Length);
            byte[] tmp = ArrayPool<byte>.Shared.Rent(mainData.Length);
            try
            {
                mainData.CopyTo(tmp.AsSpan(0, mainData.Length));
                writer.Write(tmp, 0, mainData.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tmp, clearArray: true);
            }
            writer.Write((int)salt.Length);
            writer.Write(salt);
            writer.Write((int)i);
            writer.Write((int)t);
            return ms.ToArray();
        }

        private int GetDependentIndex(ReadOnlySpan<byte> prevBlock, int maxIndex)
        {
            if (maxIndex == 0) return 0;
            ulong j_long = BitConverter.ToUInt64(prevBlock);
            return (int)(j_long % (ulong)maxIndex);
        }

        private int GetIndependentIndex(int i, byte[] salt, int t, int maxIndex)
        {
            if (maxIndex == 0) return 0;

            Span<byte> small = stackalloc byte[4 + 4 + 4 + salt.Length];
            int pos = 0;
            BinaryPrimitives.WriteInt32LittleEndian(small.Slice(pos, 4), i); pos += 4;
            BinaryPrimitives.WriteInt32LittleEndian(small.Slice(pos, 4), t); pos += 4;
            BinaryPrimitives.WriteInt32LittleEndian(small.Slice(pos, 4), salt.Length); pos += 4;
            salt.AsSpan().CopyTo(small.Slice(pos, salt.Length));

            Span<byte> digest = stackalloc byte[SHA512_SIZE];
            SHA512.HashData(small, digest);

            ulong j_long = BitConverter.ToUInt64(digest);
            CryptographicOperations.ZeroMemory(digest);
            return (int)(j_long % (ulong)maxIndex);
        }

        private void InternalSpongeHash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            ulong[] state = ArrayPool<ulong>.Shared.Rent(STATE_WIDTH_ULONGS);
            Array.Clear(state, 0, STATE_WIDTH_ULONGS);

            try
            {
                int offset = 0;
                while (offset < input.Length)
                {
                    int bytesToProcess = Math.Min(_keccakRateBytes, input.Length - offset);
                    AbsorbBlock(state, input.Slice(offset, bytesToProcess));
                    offset += bytesToProcess;
                    if (bytesToProcess == _keccakRateBytes)
                        KeccakF1600_Permutation(state);
                }

                byte[] paddedBlock = ArrayPool<byte>.Shared.Rent(_keccakRateBytes);
                try
                {
                    Span<byte> padSpan = paddedBlock.AsSpan(0, _keccakRateBytes);
                    padSpan.Clear();
                    int lastBlockSize = input.Length % _keccakRateBytes;
                    if (lastBlockSize > 0)
                        input.Slice(input.Length - lastBlockSize).CopyTo(padSpan);
                    padSpan[lastBlockSize] = 0x06;
                    padSpan[_keccakRateBytes - 1] |= 0x80;

                    AbsorbBlock(state, padSpan);
                    KeccakF1600_Permutation(state);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(paddedBlock, clearArray: true);
                }

                int outputGenerated = 0;
                while (outputGenerated < output.Length)
                {
                    int bytesToSqueeze = Math.Min(_keccakRateBytes, output.Length - outputGenerated);
                    SqueezeBlock(state, output.Slice(outputGenerated, bytesToSqueeze));
                    outputGenerated += bytesToSqueeze;
                    if (outputGenerated < output.Length)
                        KeccakF1600_Permutation(state);
                }
            }
            finally
            {
                ArrayPool<ulong>.Shared.Return(state, clearArray: true);
            }
        }

        private void AbsorbBlock(ulong[] state, ReadOnlySpan<byte> block)
        {
            for (int i = 0; i < block.Length; ++i)
            {
                int idx = i / 8;
                int shift = (i % 8) * 8;
                state[idx] ^= (ulong)block[i] << shift;
            }
        }

        private void SqueezeBlock(ulong[] state, Span<byte> outSpan)
        {
            for (int i = 0; i < outSpan.Length; ++i)
            {
                int idx = i / 8;
                int shift = (i % 8) * 8;
                outSpan[i] = (byte)(state[idx] >> shift);
            }
        }

        private void KeccakF1600_Permutation(ulong[] state)
        {
            ulong[,] A = new ulong[5, 5];
            for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++) A[x, y] = state[x + 5 * y];

            for (int round = 0; round < KECCAK_ROUNDS; round++)
            {
                ulong[] C = new ulong[5];
                for (int x = 0; x < 5; x++) C[x] = A[x, 0] ^ A[x, 1] ^ A[x, 2] ^ A[x, 3] ^ A[x, 4];
                ulong[] D = new ulong[5];
                for (int x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ RotateLeft64(C[(x + 1) % 5], 1);
                for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A[x, y] ^= D[x];

                ulong[,] B = new ulong[5, 5];
                for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) B[x, y] = RotateLeft64(A[x, y], RotationOffsets[x, y]);
                ulong[,] A2 = new ulong[5, 5];
                for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) A2[y, (2 * x + 3 * y) % 5] = B[x, y];

                for (int y = 0; y < 5; y++)
                {
                    ulong[] T = new ulong[5];
                    for (int x = 0; x < 5; x++) T[x] = A2[x, y];
                    for (int x = 0; x < 5; x++) A[x, y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
                }

                A[0, 0] ^= RoundConstants[round];
            }

            for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++) state[x + 5 * y] = A[x, y];
        }

        private static ulong RotateLeft64(ulong value, int count)
        {
            count &= 63;
            return (value << count) | (value >> (64 - count));
        }

        public void Dispose()
        {
            _disposed = true;
        }
    }

    internal static class SHA512Extensions
    {
        public static bool HashData(byte[] source, Span<byte> destination)
        {
            try
            {
                SHA512.HashData(source.AsSpan(), destination);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static bool HashData(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            try
            {
                SHA512.HashData(source, destination);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}