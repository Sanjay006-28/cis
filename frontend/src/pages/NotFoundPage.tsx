import { Link } from "react-router-dom";

export function NotFoundPage() {
  return <section className="panel"><h1>Page not found</h1><p className="section-description">The requested workspace section does not exist.</p><Link className="button button-primary" to="/">Return to overview</Link></section>;
}
