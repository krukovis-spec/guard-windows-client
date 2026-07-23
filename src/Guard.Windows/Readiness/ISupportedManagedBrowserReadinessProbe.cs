using System.Threading;
using Guard.Domain.Readiness;

namespace Guard.Windows.Readiness
{
    public interface ISupportedManagedBrowserReadinessProbe
    {
        SupportedManagedBrowserProbeFact Probe(CancellationToken cancellationToken);
    }
}
