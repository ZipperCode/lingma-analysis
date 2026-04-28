interface Props {
  page: number;
  total: number;
  limit: number;
  onChange: (page: number) => void;
}

export function Pagination({ page, total, limit, onChange }: Props) {
  const pages = Math.max(1, Math.ceil(total / limit));
  return (
    <div className="pagination">
      <button className="btn" disabled={page <= 1} onClick={() => onChange(page - 1)}>← 上一页</button>
      <span>{page} / {pages}</span>
      <button className="btn" disabled={page >= pages} onClick={() => onChange(page + 1)}>下一页 →</button>
    </div>
  );
}
