# Coulson application lifecycle

Coulson gives development applications stable addresses and starts managed applications when needed.

## Language

**Enabled application**: An application permitted to accept traffic and start on demand. Being enabled does not imply that it is running.

**Sleeping application**: An enabled managed application with no active startup or running process. A future request may start it.

**Starting application**: A managed application preparing or starting its primary service, which has not yet passed its startup readiness check.

**Ready application**: An application's primary service has passed its startup readiness check and has not subsequently been observed to exit. Readiness does not guarantee continued application-level health.

**Failed application**: An application whose latest startup failed or whose primary service unexpectedly exited. A deliberate retry or new request may start it again.

**Disabled application**: An application administratively excluded from normal routing and automatic startup.

**Unknown application status**: There is insufficient current information to determine the application's lifecycle state, including externally managed services or an unreachable daemon.
