using System.Threading;

namespace Guard.Service
{
    internal sealed class ServiceExitStatus
    {
        public const int Success = 0;
        public const int FatalRuntimeFailure = 6;

        private int _exitCode;

        public int ExitCode => Volatile.Read(ref _exitCode);

        public void MarkFatalRuntimeFailure()
        {
            Interlocked.CompareExchange(
                ref _exitCode,
                FatalRuntimeFailure,
                Success);
        }
    }
}
