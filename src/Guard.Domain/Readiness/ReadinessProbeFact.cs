using System;

namespace Guard.Domain.Readiness
{
    public sealed class ReadinessProbeFact
    {
        public ReadinessProbeFact(ReadinessFactState state)
        {
            if (!Enum.IsDefined(typeof(ReadinessFactState), state))
            {
                throw new ArgumentOutOfRangeException(nameof(state));
            }

            State = state;
        }

        public ReadinessFactState State { get; }
    }
}
