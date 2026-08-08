#!/usr/bin/env python3
"""Check unsigned BuildKit attestation descriptor/predicate annotation presence.

This verifier checks registry manifest structure and predicate annotations. It
does not fetch attestation layer payloads, validate their schemas or subjects,
verify a signature, or establish a provenance trust root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
IN_TOTO = "application/vnd.in-toto+json"
REFERENCE_TYPE = "vnd.docker.reference.type"
REFERENCE_DIGEST = "vnd.docker.reference.digest"
PREDICATE_TYPE = "in-toto.io/predicate-type"
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_PREDICATES = {
    "https://slsa.dev/provenance/v0.2",
    "https://slsa.dev/provenance/v1",
}
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
GHCR_SEGMENT = r"[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?"
GHCR_IMAGE = re.compile(rf"ghcr\.io/{GHCR_SEGMENT}/{GHCR_SEGMENT}")
MAX_RAW_BYTES = 8 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 1024 * 1024 * 1024
MAX_INDEX_DESCRIPTORS = 16
MAX_ATTESTATION_LAYERS = 16
EXPECTED_PLATFORM = {"architecture": "amd64", "os": "linux"}
ATTESTATION_PLATFORM = {"architecture": "unknown", "os": "unknown"}


class AttestationError(RuntimeError):
    """Registry metadata did not meet the unsigned presence contract."""


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("registry metadata contains a duplicate JSON key")
        result[key] = value
    return result


def inspect_raw(
    reference: str, expected_digest: str, label: str
) -> tuple[Mapping[str, Any], int]:
    """Fetch one raw manifest without reflecting registry stderr or payloads."""

    try:
        result = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", "--raw", reference],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AttestationError(f"could not inspect {label}") from exc
    if result.returncode != 0:
        raise AttestationError(f"could not inspect {label}")
    if not result.stdout or len(result.stdout) > MAX_RAW_BYTES:
        raise AttestationError(f"{label} metadata has an invalid size")
    actual_digest = "sha256:" + hashlib.sha256(result.stdout).hexdigest()
    if actual_digest != expected_digest:
        raise AttestationError(f"{label} bytes do not match the requested digest")
    try:
        value = json.loads(result.stdout, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, AttestationError) as exc:
        raise AttestationError(f"{label} metadata is not unambiguous JSON") from exc
    if not isinstance(value, dict):
        raise AttestationError(f"{label} metadata is not a JSON object")
    return value, len(result.stdout)


def descriptor_identity(descriptor: Any, label: str) -> tuple[str, int]:
    if not isinstance(descriptor, dict):
        raise AttestationError(f"{label} descriptor is not an object")
    digest = descriptor.get("digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise AttestationError(f"{label} descriptor has an invalid digest")
    size = descriptor.get("size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > MAX_DESCRIPTOR_BYTES
    ):
        raise AttestationError(f"{label} descriptor has an invalid size")
    return digest, size


def parse_index(
    index: Mapping[str, Any],
) -> tuple[set[str], list[tuple[str, str, int]]]:
    """Return image and descriptor-reference-linked attestation digests."""

    if index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX:
        raise AttestationError("built digest is not an OCI image index")
    manifests = index.get("manifests")
    if (
        not isinstance(manifests, list)
        or not manifests
        or len(manifests) > MAX_INDEX_DESCRIPTORS
    ):
        raise AttestationError("built OCI index has an invalid descriptor count")

    image_digests: set[str] = set()
    attestations: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for descriptor in manifests:
        digest, size = descriptor_identity(descriptor, "index")
        if digest in seen:
            raise AttestationError("built OCI index contains duplicate descriptor digests")
        seen.add(digest)
        annotations = descriptor.get("annotations", {})
        if not isinstance(annotations, dict):
            raise AttestationError("index descriptor annotations are malformed")
        has_reference_type = REFERENCE_TYPE in annotations
        has_reference_digest = REFERENCE_DIGEST in annotations
        reference_type = annotations.get(REFERENCE_TYPE)
        if has_reference_type and reference_type == "attestation-manifest":
            if descriptor.get("mediaType") != OCI_MANIFEST:
                raise AttestationError("attestation descriptor has an invalid media type")
            platform = descriptor.get("platform")
            if platform != ATTESTATION_PLATFORM:
                raise AttestationError(
                    "attestation descriptor lacks BuildKit's unknown platform marker"
                )
            target = annotations.get(REFERENCE_DIGEST)
            if not isinstance(target, str) or not DIGEST.fullmatch(target):
                raise AttestationError(
                "attestation descriptor has an invalid reference digest"
                )
            attestations.append((digest, target, size))
        elif not has_reference_type:
            if has_reference_digest:
                raise AttestationError(
                    "image descriptor has a reference digest without a reference type"
                )
            if descriptor.get("mediaType") != OCI_MANIFEST:
                raise AttestationError("image descriptor has an invalid media type")
            if descriptor.get("platform") != EXPECTED_PLATFORM:
                raise AttestationError(
                    "built OCI index does not contain exactly one linux/amd64 image"
                )
            image_digests.add(digest)
        else:
            raise AttestationError(
                "built OCI index has an unsupported reference descriptor"
            )

    if not image_digests:
        raise AttestationError("built OCI index has no image manifest")
    if len(image_digests) != 1:
        raise AttestationError(
            "built OCI index does not contain exactly one linux/amd64 image"
        )
    if not attestations:
        raise AttestationError("built OCI index has no BuildKit attestation manifest")
    for _, target, _ in attestations:
        if target not in image_digests:
            raise AttestationError(
                "attestation descriptor does not reference an image in the built OCI index"
            )
    referenced_images = {target for _, target, _ in attestations}
    if referenced_images != image_digests:
        raise AttestationError(
            "not every image manifest has an attestation descriptor reference"
        )
    return image_digests, attestations


def predicates_from_manifest(manifest: Mapping[str, Any]) -> list[str]:
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != OCI_MANIFEST:
        raise AttestationError("attestation metadata is not an OCI image manifest")
    config = manifest.get("config")
    descriptor_identity(config, "attestation config")
    if not isinstance(config, dict) or config.get("mediaType") != OCI_CONFIG:
        raise AttestationError("attestation config has an invalid media type")
    layers = manifest.get("layers")
    if (
        not isinstance(layers, list)
        or not layers
        or len(layers) > MAX_ATTESTATION_LAYERS
    ):
        raise AttestationError("attestation manifest has an invalid layer count")
    predicates: list[str] = []
    layer_digests: set[str] = set()
    for layer in layers:
        digest, _ = descriptor_identity(layer, "attestation layer")
        if digest in layer_digests:
            raise AttestationError(
                "attestation manifest contains duplicate layer digests"
            )
        layer_digests.add(digest)
        if layer.get("mediaType") != IN_TOTO:
            raise AttestationError("attestation layer is not in-toto metadata")
        annotations = layer.get("annotations")
        if not isinstance(annotations, dict):
            raise AttestationError("attestation layer annotations are malformed")
        predicate = annotations.get(PREDICATE_TYPE)
        if not isinstance(predicate, str) or not predicate:
            raise AttestationError("attestation layer has no predicate annotation")
        predicates.append(predicate)
    return predicates


def check_presence(image: str, built_digest: str) -> None:
    if not GHCR_IMAGE.fullmatch(image) or not DIGEST.fullmatch(built_digest):
        raise AttestationError("build outputs are malformed")
    index, _ = inspect_raw(
        f"{image}@{built_digest}", built_digest, "the exact built digest"
    )
    image_digests, attestations = parse_index(index)
    predicates_by_image = {digest: [] for digest in image_digests}
    for attestation_digest, target_digest, descriptor_size in attestations:
        manifest, raw_size = inspect_raw(
            f"{image}@{attestation_digest}",
            attestation_digest,
            "an attestation manifest",
        )
        if raw_size != descriptor_size:
            raise AttestationError(
                "attestation manifest bytes do not match the descriptor size"
            )
        predicates_by_image[target_digest].extend(predicates_from_manifest(manifest))
    for predicates in predicates_by_image.values():
        if predicates.count(SPDX_PREDICATE) != 1:
            raise AttestationError(
                "an image manifest does not have exactly one SPDX SBOM predicate annotation"
            )
        if sum(predicate in SLSA_PREDICATES for predicate in predicates) != 1:
            raise AttestationError(
                "an image manifest does not have exactly one SLSA provenance predicate annotation"
            )
        if len(predicates) != 2:
            raise AttestationError(
                "an image manifest has unsupported predicate annotations"
            )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="lowercase ghcr.io owner/image")
    parser.add_argument("--digest", required=True, help="exact built OCI index digest")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        check_presence(args.image, args.digest)
    except AttestationError as exc:
        print(
            "Unsigned attestation descriptor/predicate annotation presence "
            f"check failed: {exc}",
            file=sys.stderr,
        )
        return 1
    print(
        "Unsigned attestation descriptor/predicate annotation presence check "
        "passed for the exact built digest; layer payload schemas and subjects "
        "were not fetched or verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
