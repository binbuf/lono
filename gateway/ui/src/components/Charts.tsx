interface SeriesDef {
  name: string;
  color: string;
  values: number[];
}

/** Compact multi-series area/line chart rendered as inline SVG. */
export function TimeSeriesChart({
  labels,
  series,
  height = 190,
  format = (n: number) => String(n),
}: {
  labels: string[];
  series: SeriesDef[];
  height?: number;
  format?: (n: number) => string;
}) {
  const width = 720;
  const padL = 42;
  const padR = 12;
  const padT = 12;
  const padB = 26;
  const innerW = width - padL - padR;
  const innerH = height - padT - padB;
  const maxValue = Math.max(1, ...series.flatMap((s) => s.values));
  const n = labels.length;
  const x = (i: number) => padL + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => padT + innerH - (v / maxValue) * innerH;

  const ticks = 4;
  const labelEvery = Math.max(1, Math.ceil(n / 8));

  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style={{ height }}>
      {Array.from({ length: ticks + 1 }, (_, i) => {
        const value = (maxValue / ticks) * i;
        const yy = y(value);
        return (
          <g key={i}>
            <line className="gridline" x1={padL} x2={width - padR} y1={yy} y2={yy} />
            <text x={padL - 6} y={yy + 3} textAnchor="end">
              {format(Math.round(value))}
            </text>
          </g>
        );
      })}
      {series.map((s) => {
        const line = s.values.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
        const area = `${line} L${x(n - 1).toFixed(1)},${(padT + innerH).toFixed(1)} L${x(0).toFixed(1)},${(padT + innerH).toFixed(1)} Z`;
        return (
          <g key={s.name}>
            <path d={area} fill={s.color} opacity={0.14} />
            <path d={line} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
          </g>
        );
      })}
      {labels.map((label, i) =>
        i % labelEvery === 0 ? (
          <text key={i} x={x(i)} y={height - 6} textAnchor="middle">
            {label}
          </text>
        ) : null,
      )}
    </svg>
  );
}

export function ChartLegend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <div className="legend">
      {items.map((it) => (
        <span key={it.name}>
          <span className="sw" style={{ background: it.color }} />
          {it.name}
        </span>
      ))}
    </div>
  );
}

export function BarList({ items, color }: { items: { name: string; count: number }[]; color?: string }) {
  if (!items.length) return <div className="empty-state">No data yet</div>;
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="bars">
      {items.map((it) => (
        <div className="bar-row" key={it.name}>
          <span className="bar-name" title={it.name}>
            {it.name}
          </span>
          <span className="bar-track">
            <span
              className="bar-fill"
              style={{ width: `${Math.max(2, (it.count / max) * 100)}%`, background: color }}
            />
          </span>
          <span className="bar-val">{it.count}</span>
        </div>
      ))}
    </div>
  );
}

const DONUT_COLORS = ["#4da3ff", "#7c5cff", "#35d07f", "#f0b429", "#ff5c5c", "#39c0ed", "#c084fc", "#4ade80"];

export function Donut({ slices }: { slices: { name: string; value: number }[] }) {
  const total = slices.reduce((sum, s) => sum + s.value, 0);
  if (!total) return <div className="empty-state">No data yet</div>;
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  return (
    <div style={{ display: "flex", gap: 18, alignItems: "center", flexWrap: "wrap" }}>
      <svg width={150} height={150} viewBox="0 0 150 150">
        <g transform="translate(75,75) rotate(-90)">
          <circle r={radius} fill="none" stroke="#1e2733" strokeWidth={18} />
          {slices.map((s, i) => {
            const fraction = s.value / total;
            const dash = fraction * circumference;
            const el = (
              <circle
                key={s.name}
                r={radius}
                fill="none"
                stroke={DONUT_COLORS[i % DONUT_COLORS.length]}
                strokeWidth={18}
                strokeDasharray={`${dash} ${circumference - dash}`}
                strokeDashoffset={-offset}
              />
            );
            offset += dash;
            return el;
          })}
        </g>
        <text x={75} y={72} textAnchor="middle" style={{ fill: "#d8e0ea", fontSize: 20, fontWeight: 700 }}>
          {total}
        </text>
        <text x={75} y={90} textAnchor="middle" style={{ fontSize: 10 }}>
          findings
        </text>
      </svg>
      <div className="legend" style={{ flexDirection: "column", gap: 6 }}>
        {slices.map((s, i) => (
          <span key={s.name}>
            <span className="sw" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
            {s.name} · {s.value} ({Math.round((s.value / total) * 100)}%)
          </span>
        ))}
      </div>
    </div>
  );
}