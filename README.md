# traceroute-exporter

A small Go HTTP exporter that runs Linux `traceroute` per scrape and emits Prometheus metrics suitable for Grafana tree/node graph visualizations.

It is compatible with a blackbox-exporter style Prometheus scrape config: Prometheus sends the target as `?target=...` to `/trace`.

## Build

```bash
go build -o traceroute-exporter .
./traceroute-exporter --web.listen-address=:9805
```

Docker:

```bash
docker build -t traceroute-exporter .
docker run --rm --network host --cap-add=NET_RAW traceroute-exporter
```

`traceroute -I` and `traceroute -T` usually need raw-socket privileges. In Docker, use `--cap-add=NET_RAW` or run with appropriate capabilities.

## Code layout

The exporter is split into small package files instead of one large source file:

- `main.go`: process startup and flags
- `handlers.go`: HTTP endpoints
- `traceroute.go`: traceroute execution and target parsing
- `parser.go`: Linux traceroute output parser
- `loop.go`: routing-loop detection and give-up logic
- `metrics.go`: Prometheus exposition helpers
- `webconfig.go`: Prometheus exporter `web.yml` TLS/basic-auth support
- `dashboard.go`: embedded single-trace dashboard
- `types.go` and `util.go`: shared types/helpers

## Prometheus config

Use `__address__`, not Markdown bold text, and use a plain target string, not a Markdown link:

```yaml
scrape_configs:
  - job_name: traceroute
    scrape_interval: 60s
    scrape_timeout: 60s
    metrics_path: /trace
    static_configs:
      - targets:
          - example.com:443
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: target
      - target_label: __address__
        replacement: 127.0.0.1:9805
```

With `example.com:443`, the exporter defaults to TCP traceroute (`traceroute -T -p 443 ...`). Without a port, it defaults to ICMP (`traceroute -I ...`). You can override with `method=tcp|icmp|udp|auto`.

## Probe endpoint

```bash
curl 'http://127.0.0.1:9805/trace?target=example.com:443&debug=1'
```

## Embedded single-trace dashboard

The exporter includes a dependency-free dashboard served by the binary:

```text
http://127.0.0.1:9805/dashboard?target=example.com:443
```

The page runs one trace at a time, parses the exported Prometheus text from `/trace`, and renders a simple SVG tree. Synthetic non-responding hops such as `no-reply-hop-02` are shown as dashed/amber nodes so missing ICMP/TCP TTL replies do not break the path.


Optional query params:

- `method=tcp|icmp|udp|auto`
- `max_hops=30`
- `queries=1`
- `wait=1s`
- `timeout=55s`
- `ip_family=4|6`
- `loop_max_repeats=4` (`0` disables loop detection for that probe)
- `loop_detection=false` disables loop detection for that probe
- `debug=1`

The defaults are chosen to fit a 60s scrape timeout.

## Routing-loop detection

Loop detection is enabled by default. The exporter gives up when the current responding-hop pattern has appeared four consecutive times, for example:

```text
A -> B -> A -> B -> A -> B -> A -> B
```

For that example the repeated pattern is `A -> B` and the repeat count is `4`. The default can be changed with:

```bash
./traceroute-exporter --traceroute.loop-max-repeats=4
```

or per probe with:

```text
/trace?target=example.com:443&loop_max_repeats=4
```

Set `loop_max_repeats=0` or `loop_detection=false` to disable it. When loop detection is enabled, the exporter probes hop-by-hop with `traceroute -f N -m N` so it can stop before reaching `max_hops`. Non-responding hops are still emitted as synthetic nodes and are ignored for loop matching, so `* * *` does not create a false loop.

Loop metrics:

- `traceroute_loop_detected`: `1` when a repeated responding-hop pattern exists.
- `traceroute_loop_giveup`: `1` when tracing stopped because the repeat threshold was reached.
- `traceroute_loop_info{start_hop,end_hop,length,repeats,pattern}`: details of the repeated suffix.

## Prometheus exporter `web.yml` support

The exporter supports the usual Prometheus exporter-toolkit-style `web.yml` file for TLS, HTTP/2, optional response headers, and bcrypt basic auth.

Start with an explicit file:

```bash
./traceroute-exporter --web.listen-address=:9805 --web.config.file=/etc/traceroute-exporter/web.yml
```

or place `web.yml` / `web.yaml` next to the binary and it will be loaded automatically. `WEB_CONFIG_FILE` can also be used as an environment variable. `--web.config` is accepted as an alias for `--web.config.file`.

Minimal basic-auth example:

```yaml
basic_auth_users:
  prometheus: $2y$10$replace_with_bcrypt_hash
```

TLS example:

```yaml
tls_server_config:
  cert_file: /etc/traceroute-exporter/server.crt
  key_file: /etc/traceroute-exporter/server.key
  min_version: TLS12
  max_version: TLS13
http_server_config:
  http2: true
basic_auth_users:
  prometheus: $2y$10$replace_with_bcrypt_hash
```

See `web.yml.example` in this directory for a commented template. When TLS/basic auth is enabled, update the Prometheus scrape job with `scheme: https`, `tls_config`, and `basic_auth` as needed.

## Graph metrics

Important metrics:

- `traceroute_node_info{node,hostname,address,hop,responded,role}`: one sample per graph node.
- `traceroute_tree_edge_info{parent,node,parent_hostname,node_hostname,parent_hop,node_hop,...}`: parent-child edges for tree graph panels.
- `traceroute_edge_info{source,destination,source_hostname,destination_hostname,...}`: generic graph edge metric. It deliberately uses `destination` instead of `target` so it does not collide with the Prometheus `target` label from the relabel config.
- `traceroute_hop_rtt_seconds{node,hostname,address,hop,probe}` and `traceroute_hop_rtt_avg_seconds{...}`: RTT data.
- `traceroute_hop_probe_loss_ratio{node,hostname,address,hop}`: ratio of `*` probes for the hop.
- `traceroute_probe_success`: `1` when traceroute reached the final destination, otherwise `0`.

Non-responding hops are **not omitted**. For a `* * *` hop, the exporter emits a synthetic node such as:

```text
traceroute_node_info{hop="2",node="no-reply-hop-02",hostname="no-reply-hop-02",address="*",responded="false",role="hop",...} 1
traceroute_tree_edge_info{parent="192.0.2.1",node="no-reply-hop-02",node_hostname="no-reply-hop-02",node_address="*",node_responded="false",...} 1
```

So the tree remains continuous even when a router does not answer ICMP/TCP TTL-expired probes.

## Grafana usage

For a tree panel, query:

```promql
traceroute_tree_edge_info{job="traceroute", target="$target"}
```

Use labels `parent` and `node` as the edge endpoints, and labels such as `parent_hostname`, `node_hostname`, `parent_hop`, `node_hop`, and `node_responded` for display.

For a node graph style panel, query:

```promql
traceroute_edge_info{job="traceroute", target="$target"}
```

Then transform labels to fields and map `source` to source and `destination` to target/destination in the panel.
