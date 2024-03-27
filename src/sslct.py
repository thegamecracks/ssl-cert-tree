from __future__ import annotations

import argparse
import collections
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import Tk
from tkinter.ttk import Frame, Treeview
from typing import Generic, Iterable, Self, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import Certificate, Name, load_pem_x509_certificates

CERTIFICATE_GLOB_PATTERNS = ("*.pem", "*.crt", "*.ca-bundle", "*.cer")

T = TypeVar("T")

log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity",
    )
    parser.add_argument(
        "directory",
        default=".",
        help="The directory to find certificates in",
        nargs="?",
        type=parse_dir_path,
    )

    args = parser.parse_args()
    verbose: int = args.verbose
    directory: Path = args.directory

    configure_logging(verbose)
    enable_windows_dpi_awareness()

    app = Tk()
    app.title("SSL Certificate Tree")
    app.geometry("600x600")
    app.grid_columnconfigure(0, weight=1)
    app.grid_rowconfigure(0, weight=1)

    frame = CertFrame(app)
    frame.find_certificates(directory)
    frame.render()
    frame.grid(row=0, column=0, sticky="nesw")

    app.mainloop()


def parse_dir_path(s: str) -> Path:
    p = Path(s)
    if not p.is_dir():
        raise ValueError(f"Not a directory: {s}")
    return p


def enable_windows_dpi_awareness():
    if sys.platform == "win32":
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(2)


def configure_logging(verbose: int) -> None:
    if verbose == 0:
        fmt = "%(levelname)s: %(message)s"
        level = logging.WARNING
    elif verbose == 1:
        fmt = "%(levelname)s: %(message)s"
        level = logging.INFO
    else:
        fmt = "%(levelname)s: %(message)-50s (%(name)s#L%(lineno)d)"
        level = logging.DEBUG

    logging.basicConfig(level=level, format=fmt)


class CertFrame(Frame):
    def __init__(self, parent: Tk) -> None:
        super().__init__(parent, padding=10)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.cert_tree = CertTree()
        self.treeview = Treeview(self, show="tree")
        self.treeview.grid(row=0, column=0, sticky="nesw")

    def find_certificates(self, directory: Path) -> None:
        """Non-recursively search the given directory for certificates to load."""
        log.debug(f"Finding certificates at directory: %s", directory)
        for pattern in CERTIFICATE_GLOB_PATTERNS:
            for file in directory.glob(pattern):
                log.debug("Loading %s", file)
                certs = load_pem_x509_certificates(file.read_bytes())
                log.debug("Adding %d certificate(s)", len(certs))
                for cert in certs:
                    self.cert_tree.add(cert)

        for issuer in self.cert_tree.unresolved_issuers():
            log.debug("Unresolved issuer: %s", issuer)

    def render(self, node: Node[Certificate] | None = None) -> None:
        """Render the certificate tree."""
        if node is None:
            self.treeview.delete(*self.treeview.get_children())
            roots = self.cert_tree.roots()
            total = len(roots) + sum(len(root.descendants()) for root in roots)
            log.debug("Rendering %d certificates with %d root(s)", total, len(roots))
            for root in roots:
                self.render(root)
            return

        node_id = self._get_node_id(node)
        if len(node.parents) > 0:
            parent_id = self._get_node_id(node.parents[0])
        else:
            parent_id = ""

        self.treeview.insert(parent_id, "end", id=node_id, text=str(node.val.subject))

        for child in node.children:
            self.render(child)

    def _get_node_id(self, node: Node[Certificate]) -> str:
        return node.val.fingerprint(SHA256()).hex(":")


class CertTree:
    _subject_nodes: dict[Name, list[Node[Certificate]]]
    _unresolved_issuers: dict[Name, list[Node[Certificate]]]

    def __init__(self, certificates: Iterable[Certificate] = ()) -> None:
        self._subject_nodes = collections.defaultdict(list)
        self._unresolved_issuers = collections.defaultdict(list)
        for cert in certificates:
            self.add(cert)

    def roots(self) -> list[Node[Certificate]]:
        """Return a list of root certificates, that being certificates
        which are self-signed.
        """
        return [
            node
            for nodes in self._subject_nodes.values()
            for node in nodes
            if len(node.parents) == 0
        ]

    def unresolved_issuers(self) -> list[Name]:
        """Return a list of issuer names that are required by one
        or more certificates.
        """
        return [
            name for name, nodes in self._unresolved_issuers.items() if len(nodes) > 0
        ]

    def add(self, cert: Certificate) -> Node[Certificate]:
        """Add a certificate to the tree."""
        nodes = self._subject_nodes[cert.subject]
        for node in nodes:
            if node.val == cert:
                return node

        node = Node(cert)
        nodes.append(node)

        resolved = self._resolve_issuer(node)
        if not resolved:
            self._unresolved_issuers[cert.issuer].append(node)

        for unresolved in self._unresolved_issuers[cert.subject].copy():
            self._resolve_issuer(unresolved, retroactive=True)

        return node

    def _resolve_issuer(
        self,
        node: Node[Certificate],
        retroactive: bool = False,
    ) -> bool:
        for issuer in self._subject_nodes[node.val.issuer]:
            try:
                node.val.verify_directly_issued_by(issuer.val)
            except (ValueError, TypeError, InvalidSignature):
                continue
            else:
                if node is issuer:
                    log.debug("Self-signed certificate: %s", node.val.subject)
                    return True

                if retroactive:
                    log.debug("Retroactively resolved issuer for: %s", node.val.subject)
                else:
                    log.debug("Resolved issuer for: %s", node.val.subject)

                issuer.add_child(node)

                try:
                    self._unresolved_issuers[node.val.issuer].remove(node)
                except ValueError:
                    pass

                return True

        return False


@dataclass
class Node(Generic[T]):
    """A node containing an abritrary value in a directed acyclic graph."""

    val: T
    """The value for this node."""
    children: list[Self] = field(default_factory=list, repr=False)
    """A list of the node's immediate children.

    For a list of all descendants, see :meth:`descendants()`.

    """
    parents: list[Self] = field(default_factory=list, repr=False)
    """A list of the node's ancestors."""

    def descendants(self) -> list[Self]:
        """Return a list of descendants in breadth-first order."""
        descendants = self.children
        i = 0
        while i < len(descendants):
            descendants.extend(descendants[i].children)
            i += 1
        return descendants

    def add_child(self, child: Self) -> None:
        """Add another node as a child of this node.

        This recursively updates the parents of the child node.

        """
        if child is self:
            raise ValueError("Cannot add self as a child")
        if len(child.parents) > 0:
            raise ValueError("Node already has a parent")

        self.children.append(child)
        child._add_parent(self)

    def remove_child(self, child: Self) -> None:
        """Remove another node from this node's children, if present.

        This recursively updates the parents of the child node.

        """
        try:
            self.children.remove(child)
        except ValueError:
            pass
        else:
            child._remove_parent(self)

    def _add_parent(self, parent: Self) -> None:
        self.parents.append(parent)
        self.parents.extend(parent.parents)
        for child in self.children:
            child._add_parent(parent)

    def _remove_parent(self, parent: Self) -> None:
        self.parents.remove(parent)

        # WARNING: O(n^2) worst case, maybe slice the parents instead?
        for grandparent in parent.parents:
            self.parents.remove(grandparent)

        for child in self.children:
            child._remove_parent(parent)


if __name__ == "__main__":
    main()