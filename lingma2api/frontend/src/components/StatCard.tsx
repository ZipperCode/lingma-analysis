interface Props {
  label: string;
  value: string | number;
  suffix?: string;
}

export function StatCard({ label, value, suffix }: Props) {
  return (
    <div className="stat-card">
      <div className="label">{label}</div>
      <div className="value">{value}{suffix && <span style={{ fontSize: 14, fontWeight: 400, marginLeft: 4 }}>{suffix}</span>}</div>
    </div>
  );
}
