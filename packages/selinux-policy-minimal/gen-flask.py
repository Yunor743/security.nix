"""Generate CIL class, permission and initial SID declarations.

The kernel's object classes and permissions are the same for every policy.
The reference policy keeps an up-to-date list of them, so this converts its
`policy/flask` files to CIL instead of maintaining a second copy by hand.

Usage: gen-flask.py <refpolicy>/policy/flask > flask.cil
"""

import re
import sys
from pathlib import Path


def strip_comments(text: str) -> str:
    return re.sub(r"#.*", "", text)


def main() -> None:
    flask = Path(sys.argv[1])

    classes = re.findall(
        r"^class\s+(\w+)", strip_comments((flask / "security_classes").read_text()), re.M
    )
    sids = re.findall(
        r"^sid\s+(\w+)", strip_comments((flask / "initial_sids").read_text()), re.M
    )

    vectors = strip_comments((flask / "access_vectors").read_text())
    pattern = re.compile(
        r"\b(common|class)\s+(\w+)(?:\s+inherits\s+(\w+))?(?:\s*\{([^}]*)\})?"
    )
    declared = set()
    out = []
    for kind, name, inherits, perms in pattern.findall(vectors):
        perm_list = " ".join(perms.split())
        out.append(f"({kind} {name} ({perm_list}))")
        if kind == "class":
            declared.add(name)
            if inherits:
                out.append(f"(classcommon {name} {inherits})")

    missing = [c for c in classes if c not in declared]
    if missing:
        sys.exit(f"classes without access vectors: {missing}")

    out.append(f"(classorder ({' '.join(classes)}))")

    for sid in sids:
        out.append(f"(sid {sid})")
    out.append(f"(sidorder ({' '.join(sids)}))")

    # A class map covering every permission of every class, so that base.cil
    # can grant full access in one rule.
    out.append("(classmap all_classes (any))")
    for cls in classes:
        out.append(f"(classmapping all_classes any ({cls} (all)))")

    print("\n".join(out))


if __name__ == "__main__":
    main()
