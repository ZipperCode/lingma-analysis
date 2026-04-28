interface Props {
  code: string;
  language?: string;
}

export function CodeViewer({ code }: Props) {
  let formatted = code;
  try { formatted = JSON.stringify(JSON.parse(code), null, 2); } catch {}

  return (
    <pre className="code-viewer">{formatted}</pre>
  );
}
