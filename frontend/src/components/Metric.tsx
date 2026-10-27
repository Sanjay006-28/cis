import type { LucideIcon } from "lucide-react";

type MetricProps = {
  label: string;
  value: string;
  detail?: string;
  icon: LucideIcon;
};

export function Metric({ label, value, detail, icon: Icon }: MetricProps) {
  return (
    <section className="metric-panel">
      <div className="metric-top">
        <span>{label}</span>
        <Icon size={17} aria-hidden="true" />
      </div>
      <strong>{value}</strong>
      {detail && <p>{detail}</p>}
    </section>
  );
}
