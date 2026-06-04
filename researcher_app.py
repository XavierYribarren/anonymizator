"""Anonymizator — CLI entry point (desktop mode)."""
import socket
import threading
import time
import webbrowser

import typer
import uvicorn

app_cli = typer.Typer(help="Anonymizator — Secure file encryption for research")


def _is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _find_available_port(start: int, max_attempts: int = 10) -> int:
    for port in range(start, start + max_attempts):
        if _is_port_available(port):
            return port
    raise RuntimeError(f"No available port found between {start} and {start + max_attempts}")


@app_cli.command()
def serve(
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser automatically"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
):
    """Start the Anonymizator web server."""
    if not _is_port_available(port):
        typer.echo(f"Port {port} is already in use.", err=True)
        try:
            port = _find_available_port(port + 1)
            typer.echo(f"Using port {port} instead.")
        except RuntimeError as e:
            typer.echo(str(e), err=True)
            raise typer.Exit(1)

    url = f"http://{host}:{port}"
    typer.echo(f"Starting Anonymizator on {url}")

    if open_browser:
        def _open():
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    log_level = "debug" if debug else "warning"
    uvicorn.run(
        "web.main:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=debug,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


@app_cli.command()
def version():
    """Show Anonymizator version."""
    typer.echo("Anonymizator v2.0.0")


if __name__ == "__main__":
    app_cli()
