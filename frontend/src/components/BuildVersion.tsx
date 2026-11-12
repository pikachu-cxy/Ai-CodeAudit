import { useEffect, useState } from "react";
import { api } from "../api";

export function BuildVersion() {
  const [label, setLabel] = useState("");

  useEffect(() => {
    api
      .getBuildInfo()
      .then((d) => setLabel(d.build_id ? `v${d.build_id.slice(0, 19)}` : ""))
      .catch(() => setLabel(""));
  }, []);

  if (!label) return null;
  return <p className="text-[10px] text-slate-600 mt-2 px-3 font-mono">{label}</p>;
}
