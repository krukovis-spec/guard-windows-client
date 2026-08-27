using System;

namespace Guard.Domain.Readiness
{
    public sealed class SupportedManagedBrowserProbeFact
    {
        public SupportedManagedBrowserProbeFact(ReadinessFactState state, int managedBrowserCount)
        {
            if (!Enum.IsDefined(typeof(ReadinessFactState), state))
            {
                throw new ArgumentOutOfRangeException(nameof(state));
            }

            if (managedBrowserCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(managedBrowserCount));
            }

            if (state == ReadinessFactState.Satisfied && managedBrowserCount == 0)
            {
                throw new ArgumentException("A satisfied browser fact requires at least one supported managed browser.", nameof(managedBrowserCount));
            }

            if (state != ReadinessFactState.Satisfied && managedBrowserCount != 0)
            {
                throw new ArgumentException("An unverified browser fact cannot report managed browsers.", nameof(managedBrowserCount));
            }

            State = state;
            ManagedBrowserCount = managedBrowserCount;
        }

        public ReadinessFactState State { get; }

        public int ManagedBrowserCount { get; }

    }
}
