def analyze_attachments(observations):
    # This list will hold every suspicious attachment indicator we find.
    indicators = []

    # Get the list of attachments from the observations dictionary.
    # If "attachments" does not exist, use an empty list instead.
    attachments = observations.get("attachments", [])

    # THese extensions especially risky because they can directly execute
    # code, scripts, programs, installers, or shortcuts.
    high_risk_extensions = {
        ".exe",
        ".com",
        ".scr",
        ".pif",
        ".cpl",
        ".dll",
        ".sys",
        ".drv",
        ".ocx",
        ".msi",
        ".msp",
        ".msix",
        ".appx",
        ".appxbundle",
        ".ps1",
        ".psm1",
        ".psd1",
        ".bat",
        ".cmd",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".sct",
        ".lnk",
        ".url",
        ".scf",
        ".jar",
    }

    # Microsoft Office formats that are capable of containing macros
    # or other executable content.
    macro_enabled_extensions = {
        ".docm",
        ".dotm",
        ".xlsm",
        ".xltm",
        ".xlam",
        ".xlsb",
        ".pptm",
        ".potm",
        ".ppam",
        ".ppsm",
        ".sldm",
        ".xll",
    }

    # Archive/compressed files can hide other files inside them.
    archive_extensions = {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".cab",
        ".ace",
    }

    # Disk-image files can contain complete file systems,
    # executables, scripts, shortcuts, or installers.
    disk_image_extensions = {
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
        ".dmg",
    }

    # These are potentially risky, but not as strong of an indicator
    medium_risk_extensions = {
        ".reg",
        ".inf",
        ".rtf",
        ".slk",
        ".iqy",
        ".odc",
        ".udl",
        ".one",
        ".html",
        ".htm",
        ".svg",
        ".sh",
        ".run",
        ".bin",
        ".deb",
        ".rpm",
        ".desktop",
        ".appimage",
        ".pkg",
        ".apk",
    }

    # Go through every attachment found in the email
    for attachment in attachments:

        # Pull the raw facts that observations.py collected
        filename = attachment.get("filename")
        extension = attachment.get("extension")
        content_type = attachment.get("content_type")
        size_bytes = attachment.get("size_bytes")

        # An attachment without a filename is unusual but
        # still a low-severity indicator.
        if filename is None:
            indicators.append({
                "type": "attachment",
                "subtype": "missing_filename",
                "value": None,
                "severity": "low",
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

        # If there is no file extension, cannot perform
        # extension-based analysis on this attachment.
        if extension is None:
            continue

        # Extension is lowercase so values like
        # ".EXE" and ".exe" are treated the same.
        extension = extension.lower()

        # Check whether the extension belongs to the highest-risk group.
        if extension in high_risk_extensions:
            indicators.append({
                "type": "attachment",
                "subtype": "high_risk_extension",
                "value": extension,
                "severity": "high",
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

        # If it is not high-risk, check whether it is
        # a macro-enabled Microsoft Office document.
        elif extension in macro_enabled_extensions:
            indicators.append({
                "type": "attachment",
                "subtype": "macro_enabled_document",
                "value": extension,
                "severity": "medium",
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

        # Check whether the attachment is a disk-image format
        elif extension in disk_image_extensions:
            indicators.append({
                "type": "attachment",
                "subtype": "disk_image_attachment",
                "value": extension,
                "severity": "medium",
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

        # Check whether the file is an archive or compressed container
        elif extension in archive_extensions:
            indicators.append({
                "type": "attachment",
                "subtype": "archive_attachment",
                "value": extension,
                "severity": "medium",
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

        # Check the medium-risk extension group
        elif extension in medium_risk_extensions:
            indicators.append({
                "type": "attachment",
                "subtype": "potentially_risky_extension",
                "value": extension,
                "severity": "medium",
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size_bytes,
            })

    return indicators