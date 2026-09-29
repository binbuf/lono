import { useState, type ReactNode } from "react";

interface RevealProps {
  children: ReactNode;
  secret?: boolean;
  forceOpen?: boolean;
}

/** Shows sensitive values blurred until the user explicitly reveals them. */
export function Reveal({ children, secret = true, forceOpen = false }: RevealProps) {
  const [shown, setShown] = useState(false);
  if (!secret) return <>{children}</>;
  const visible = shown || forceOpen;
  return (
    <span className={"secret" + (visible ? " revealed" : "")}>
      <span className="masked-value">{children}</span>
      {!forceOpen && (
        <button
          type="button"
          className="subtle reveal-btn"
          onClick={(e) => {
            e.stopPropagation();
            setShown((s) => !s);
          }}
        >
          {visible ? "hide" : "reveal"}
        </button>
      )}
    </span>
  );
}

/** Renders red strikethrough original + green replacement inside a chip. */
export function ChangeChip({
  kind,
  before,
  after,
  action,
  forceReveal,
  onClick,
  title,
}: {
  kind: string;
  before: string | null;
  after: string | null;
  action: string;
  forceReveal?: boolean;
  onClick?: () => void;
  title?: string;
}) {
  const removed = before || (action === "masked" ? "••••••" : "«…»");
  return (
    <span className="chip" title={title} onClick={onClick}>
      <span className="kind">{kind}</span>
      <del className="red">
        <Reveal secret={!!before} forceOpen={forceReveal}>
          {removed}
        </Reveal>
      </del>
      <span className="sep">→</span>
      <ins className="green">{after || "«removed»"}</ins>
    </span>
  );
}