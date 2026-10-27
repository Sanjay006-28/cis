import { AlertCircle, CheckCircle2, Info, LoaderCircle } from "lucide-react";

type StateMessageProps = {
  kind: "error" | "success" | "info" | "loading";
  children: React.ReactNode;
};

const icons = {
  error: AlertCircle,
  success: CheckCircle2,
  info: Info,
  loading: LoaderCircle,
};

export function StateMessage({ kind, children }: StateMessageProps) {
  const Icon = icons[kind];
  return (
    <div className={`state-message state-${kind}`} role={kind === "error" ? "alert" : "status"}>
      <Icon size={17} aria-hidden="true" className={kind === "loading" ? "animate-spin" : ""} />
      <div>{children}</div>
    </div>
  );
}
