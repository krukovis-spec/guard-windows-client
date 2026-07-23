using System.Threading;
using Guard.Domain.Readiness;

namespace Guard.Windows.Readiness
{
    public interface IReadinessProbe
    {
        ReadinessProbeFact Probe(CancellationToken cancellationToken);
    }
}
