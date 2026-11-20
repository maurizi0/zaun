# Container Deployment

Deploy the Zaun Agent Proxy in a containerized environment using Podman.

⚠️ Containers can access host services via `host.containers.internal`. Avoid exposing services that the agent should not reach when using this setup. ⚠️

## Usage

1. Build the proxy image:
   ```bash
   podman build . -t zaun-agent-proxy:latest -f Containerfile
   ```
2. Configure [`zaun-pod.yaml`](zaun-pod.yaml) and specify your agent container image and set a **UI password**!
3. Start the pod (`zaun-proxy` and `zaun-agent`):
   ```bash
   podman kube play zaun-pod.yaml
   ```
4. Access the proxy Web UI at http://127.0.0.1:18080. The agent is preconfigured to use it as an HTTP proxy and IP gateway.
5. Open an interactive shell to run your preferred agent tool:
   ```bash
   podman exec -it zaun-agent bash
   ```

## Configurable Parameters

- `VERIFY_UPSTREAM_TLS`: Enable (`1`) or disable (`0`) upstream TLS verification.
- `UI_PASSWORD`: Password for the proxy UI.
- `ports.hostPort`: Host port for accessing the proxy.
- `volumes.proxy-data.persistentVolumeClaim`: Uncomment and remove `emptyDir` to persist proxy data across sessions.
