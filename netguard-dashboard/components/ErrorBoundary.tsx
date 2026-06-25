"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = {
  children: ReactNode;
  fallback?: ReactNode;
};

type State = {
  hasError: boolean;
};

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("NetGuard component error", error, info);
  }

  override render() {
    if (this.state.hasError) {
      return this.props.fallback ?? <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-100">Component failed to render.</div>;
    }

    return this.props.children;
  }
}
