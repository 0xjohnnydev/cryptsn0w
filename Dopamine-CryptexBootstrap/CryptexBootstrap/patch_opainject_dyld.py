#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import pathlib


EXPECTED_SHA256 = "4fe459ee8039e599d1e59ce4dc8f72496cf0396b7f1700a95d6b83c481397c70"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one {label} patch site, found {count}")
    return text.replace(old, new, 1)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Adapt pinned opa334/opainject image iteration for tagged iOS 27 pointers."
    )
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()

    source_bytes = args.source.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            f"unexpected pinned opainject dyld.m hash: {digest}"
        )

    text = source_bytes.decode("utf-8")
    start = text.index("void iterateImages(")
    end = text.index("\nvm_address_t getRemoteImageAddress", start)
    replacement = r'''void iterateImages(task_t task, vm_address_t imageStartPtr, void (^iterateBlock)(char*, struct dyld_image_info*, BOOL*))
{
	struct dyld_all_image_infos imageInfos = { 0 };
	if (task_read(task, imageStartPtr, &imageInfos, sizeof(imageInfos)) != KERN_SUCCESS) return;
	if (imageInfos.infoArrayCount == 0 || imageInfos.infoArrayCount > 4096) return;

	// dyld 17 stores remote pointers with top-byte metadata. The task port APIs
	// require the canonical userspace address, so remove only the non-address
	// high bits before dereferencing values read from another process.
	vm_address_t infoArrayAddress =
		(vm_address_t)((uintptr_t)imageInfos.infoArray & 0x0000FFFFFFFFFFFFULL);
	if (infoArrayAddress == 0) return;

	size_t infoArraySize = sizeof(struct dyld_image_info) * imageInfos.infoArrayCount;
	struct dyld_image_info *infoArray = calloc(imageInfos.infoArrayCount, sizeof(struct dyld_image_info));
	if (infoArray == NULL) return;
	if (task_read(task, infoArrayAddress, &infoArray[0], infoArraySize) != KERN_SUCCESS) {
		free(infoArray);
		return;
	}

	for(uint32_t i = 0; i < imageInfos.infoArrayCount; i++)
	{
		@autoreleasepool
		{
			infoArray[i].imageLoadAddress = (const struct mach_header *)
				((uintptr_t)infoArray[i].imageLoadAddress & 0x0000FFFFFFFFFFFFULL);
			infoArray[i].imageFilePath = (const char *)
				((uintptr_t)infoArray[i].imageFilePath & 0x0000FFFFFFFFFFFFULL);
			char currentImagePath[PATH_MAX] = { 0 };
			if(task_read(task, (vm_address_t)infoArray[i].imageFilePath, &currentImagePath[0], sizeof(currentImagePath) - 1) == KERN_SUCCESS)
			{
				BOOL stop = NO;
				iterateBlock(currentImagePath, &infoArray[i], &stop);
				if(stop) break;
			}
		}
	}
	free(infoArray);
}
'''
    patched = text[:start] + replacement + text[end:]
    patched = replace_once(
        patched,
        '''\t\tif(strcmp(iterImagePath, imagePath) == 0)
\t\t{
\t\t\toutAddr = (vm_address_t)imageInfo->imageLoadAddress;
\t\t}
''',
        '''\t\tif(strcmp(iterImagePath, imagePath) == 0)
\t\t{
\t\t\toutAddr = (vm_address_t)imageInfo->imageLoadAddress;
\t\t\t*stop = YES;
\t\t}
''',
        "image lookup early stop",
    )
    patched = replace_once(
        patched,
        '''\t\t\tif(strcmp(iterSymbolName, symbolName) == 0)
\t\t\t{
\t\t\t\toutAddr = value;
\t\t\t}
''',
        '''\t\t\tif(strcmp(iterSymbolName, symbolName) == 0)
\t\t\t{
\t\t\t\toutAddr = value;
\t\t\t\t*stop = YES;
\t\t\t}
''',
        "symbol lookup early stop",
    )
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(patched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
