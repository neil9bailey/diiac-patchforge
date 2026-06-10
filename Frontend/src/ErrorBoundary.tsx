import { Component, ErrorInfo, ReactNode } from "react";

type ErrorBoundaryProps = {
  children: ReactNode;
};

type ErrorBoundaryState = {
  error: Error | null;
};

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error("PatchForge UI error boundary caught an error.", error, errorInfo);
  }

  handleReload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.error) {
      return (
        <main className="error-boundary-shell" role="alert" aria-label="PatchForge application error">
          <section className="error-boundary-panel">
            <p className="eyebrow">PatchForge</p>
            <h2>Something went wrong in the PatchForge interface</h2>
            <p className="error-boundary-message">{this.state.error.message || "An unexpected rendering error occurred."}</p>
            <p className="muted-copy">No governance state was changed. Reload to restore the governed view.</p>
            <button type="button" className="action-button" onClick={this.handleReload}>
              Reload PatchForge
            </button>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}
