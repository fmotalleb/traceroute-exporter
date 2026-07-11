const frames = context.panel.data.series || [];

const valuesArray = (field) => {
  if (!field || !field.values) return [];
  if (Array.isArray(field.values)) return field.values;
  if (field.values.toArray) return field.values.toArray();
  return Array.from(field.values);
};

const namedField = (frame, name) =>
  frame.fields.find((field) => field.name.toLowerCase() === name.toLowerCase());

const numericField = (frame) =>
  frame.fields.find((field) => field.type === 'number' && !/^time$/i.test(field.name));

const edges = [];
for (const frame of frames.filter((item) => item.refId === 'edges')) {
  const sourceField = namedField(frame, 'source');
  const targetField = namedField(frame, 'target');
  const idField = namedField(frame, 'id');

  if (sourceField && targetField) {
    const sources = valuesArray(sourceField);
    const targets = valuesArray(targetField);
    const ids = valuesArray(idField);
    for (let i = 0; i < Math.min(sources.length, targets.length); i++) {
      if (sources[i] && targets[i]) {
        edges.push({
          id: ids[i] || `${sources[i]}_to_${targets[i]}`,
          source: String(sources[i]),
          target: String(targets[i]),
        });
      }
    }
  } else {
    // Handles a Prometheus response represented as one numeric field per series.
    for (const field of frame.fields.filter((item) => item.type === 'number')) {
      const labels = field.labels || {};
      if (labels.source && labels.target) {
        edges.push({
          id: labels.id || `${labels.source}_to_${labels.target}`,
          source: String(labels.source),
          target: String(labels.target),
        });
      }
    }
  }
}

const rttMs = new Map();
for (const frame of frames.filter((item) => item.refId === 'rtt')) {
  const nodeField = namedField(frame, 'node') || namedField(frame, 'address');
  const valueField = numericField(frame);

  if (nodeField && valueField) {
    const nodes = valuesArray(nodeField);
    const values = valuesArray(valueField);
    for (let i = 0; i < Math.min(nodes.length, values.length); i++) {
      const value = Number(values[i]);
      if (nodes[i] && Number.isFinite(value)) rttMs.set(String(nodes[i]), value * 1000);
    }
  } else {
    for (const field of frame.fields.filter((item) => item.type === 'number')) {
      const labels = field.labels || {};
      const node = labels.node || labels.address;
      const values = valuesArray(field);
      const value = Number(values[values.length - 1]);
      if (node && Number.isFinite(value)) rttMs.set(String(node), value * 1000);
    }
  }
}

const nodeIds = new Set();
const children = new Map();
const indegree = new Map();
for (const edge of edges) {
  nodeIds.add(edge.source);
  nodeIds.add(edge.target);
  if (!children.has(edge.source)) children.set(edge.source, []);
  children.get(edge.source).push(edge.target);
  indegree.set(edge.target, (indegree.get(edge.target) || 0) + 1);
  if (!indegree.has(edge.source)) indegree.set(edge.source, 0);
}

if (nodeIds.size === 0) {
  return {
    title: {
      text: 'No topology data',
      subtext: 'Check the edges query and selected variables.',
      left: 'center',
      top: 'center',
    },
  };
}

// Assign vertical lanes. Shared parents are centered over their descendants.
let nextLane = 0;
const lane = new Map();
const visiting = new Set();
const placeLane = (id) => {
  if (lane.has(id)) return lane.get(id);
  if (visiting.has(id)) {
    const value = nextLane++;
    lane.set(id, value);
    return value;
  }
  visiting.add(id);
  const kids = [...new Set(children.get(id) || [])];
  let value;
  if (kids.length === 0) {
    value = nextLane++;
  } else {
    const childLanes = kids.map(placeLane);
    value = childLanes.reduce((sum, item) => sum + item, 0) / childLanes.length;
  }
  visiting.delete(id);
  lane.set(id, value);
  return value;
};

const roots = [...nodeIds].filter((id) => (indegree.get(id) || 0) === 0);
for (const root of roots) placeLane(root);
for (const id of nodeIds) placeLane(id);

/**
 * Stable bounded spacing.
 *
 * Every edge gets a readable minimum distance.
 * Latencies above one second are capped.
 */
const MIN_NODE_GAP = 300;
const MAX_NODE_GAP = 520;
const LATENCY_CAP_MS = 1000;
const VERTICAL_GAP = 240;

const latencyDelta = (source, target) => {
  const sourceRtt = rttMs.get(source);
  const targetRtt = rttMs.get(target);

  if (!Number.isFinite(sourceRtt) || !Number.isFinite(targetRtt)) {
    return null;
  }

  return Math.abs(targetRtt - sourceRtt);
};

const visualEdgeLength = (source, target) => {
  const delta = latencyDelta(source, target);

  if (!Number.isFinite(delta)) {
    return MIN_NODE_GAP;
  }

  const cappedLatency = Math.min(
    Math.max(delta, 0),
    LATENCY_CAP_MS
  );

  return (
    MIN_NODE_GAP +
    (cappedLatency / LATENCY_CAP_MS) *
      (MAX_NODE_GAP - MIN_NODE_GAP)
  );
};

/**
 * Calculate deterministic left-to-right positions.
 *
 * A child is always at least MIN_NODE_GAP to the right of
 * its parent. A node shared by several branches uses the
 * furthest required position.
 */
const xPosition = new Map();
const remainingParents = new Map(indegree);

const queue = roots.length
  ? [...roots]
  : [[...nodeIds][0]];

for (const root of queue) {
  xPosition.set(root, 0);
}

/**
 * Prevent routing cycles from repeatedly adding the same node.
 *
 * This preserves the existing layered positioning logic. It only changes
 * queue handling and ignores back-edges to nodes already positioned.
 */
const processedNodes = new Set();
const queuedNodes = new Set(queue);

while (
  queue.length > 0 ||
  processedNodes.size < nodeIds.size
) {
  /**
   * A cyclic component might not have a root. Start it from the first
   * unprocessed node when the normal root queue becomes empty.
   */
  if (queue.length === 0) {
    const cycleRoot = [...nodeIds].find(
      (id) => !processedNodes.has(id)
    );

    if (!cycleRoot) {
      break;
    }

    if (!xPosition.has(cycleRoot)) {
      xPosition.set(cycleRoot, 0);
    }

    queue.push(cycleRoot);
    queuedNodes.add(cycleRoot);
  }

  const source = queue.shift();
  queuedNodes.delete(source);

  /**
   * Every node is processed at most once.
   */
  if (processedNodes.has(source)) {
    continue;
  }

  processedNodes.add(source);

  const sourceX = xPosition.get(source) || 0;
  const targets = [
    ...new Set(children.get(source) || []),
  ];

  for (const target of targets) {
    const candidate =
      sourceX + visualEdgeLength(source, target);

    /**
     * A target already processed is a back-edge in a cycle.
     * Keep its existing position.
     */
    if (!processedNodes.has(target)) {
      xPosition.set(
        target,
        Math.max(
          xPosition.get(target) || 0,
          candidate
        )
      );
    }

    const parentsLeft =
      (remainingParents.get(target) || 1) - 1;

    remainingParents.set(
      target,
      parentsLeft
    );

    /**
     * Important:
     * - use === 0 instead of <= 0
     * - never queue an already processed/queued node
     */
    if (
      parentsLeft === 0 &&
      !processedNodes.has(target) &&
      !queuedNodes.has(target)
    ) {
      queue.push(target);
      queuedNodes.add(target);
    }
  }
}

/**
 * Deterministic fallback for cycles and disconnected nodes.
 */
for (const id of nodeIds) {
  if (!xPosition.has(id)) {
    xPosition.set(id, 0);
  }
}

const graphNodes = [...nodeIds].map((id) => {
  const latency = rttMs.get(id);

  return {
    id,
    name: id,
    value: Number.isFinite(latency)
      ? latency
      : null,
    x: xPosition.get(id) || 0,
    y: (lane.get(id) || 0) * VERTICAL_GAP,
    symbolSize: 42,

    /**
     * Keep the calculated position stable.
     */
    fixed: true,

    itemStyle: {
      color: Number.isFinite(latency)
        ? latency < 20
          ? "#56A64B"
          : latency < 100
            ? "#FFB357"
            : "#E02F44"
        : "#8e8e8e",
    },

    label: {
      show: true,
      position: "bottom",
      formatter: id,
    },
  };
});

const graphLinks = edges.map((edge) => {
  const delta = latencyDelta(
    edge.source,
    edge.target
  );
  return {
    source: edge.source,
    target: edge.target,
    value: delta,
    lineStyle: {
      width: Number.isFinite(delta) ? Math.max(1, Math.min(8, 1 + delta / 20)) : 2,
      color: Number.isFinite(delta)
        ? (delta < 20 ? '#56A64B' : delta < 100 ? '#FFB357' : '#E02F44')
        : '#8e8e8e',
      opacity: 0.85,
    },
    label: {
      show: true,
      formatter: Number.isFinite(delta) ? `${delta.toFixed(3)} ms` : 'RTT unavailable',
      fontSize: 10,
    },
  };
});

return {
  animationDurationUpdate: 400,
  tooltip: {
    formatter: (params) => {
      if (params.dataType === 'edge') {
        return `${params.data.source} → ${params.data.target}<br/>Δ RTT: ${Number.isFinite(params.data.value) ? params.data.value.toFixed(3) + ' ms' : 'unavailable'}`;
      }
      return `${params.data.name}<br/>Cumulative RTT: ${Number.isFinite(params.data.value) ? params.data.value.toFixed(3) + ' ms' : 'unavailable'}`;
    },
  },
  toolbox: { feature: { restore: {}, saveAsImage: {} } },
  series: [{
    type: 'graph',
    layout: 'none',
    roam: true,
    draggable: true,
    data: graphNodes,
    links: graphLinks,
    edgeSymbol: ['none', 'arrow'],
    edgeSymbolSize: [0, 10],
    edgeLabel: { show: true, position: 'middle' },
    emphasis: { focus: 'adjacency', lineStyle: { width: 5 } },
  }],
};
