##Bro Script to extract all files types to home directory for Bro Version 2.4.1+ (works with Zeek 2.6.1)
##Author: Rahil Chadha
##Date: 2019-03-18
##Source: https://github.com/chadharahil/bro-file-extraction
##
##For anyone else who is frustrated ever since the Bro 2.2+ update with the f$mime_type breaking & the new file_sniff as well as the lack of ##information in official documentation, the code below is my fix; feel free to use. I will try to extend based on protocols HTTP, FTP, email etc. to ##reduce overhead in the future
##
##This is my first script so feel free to send suggestions, comments, improvements or ideas at chadharahil@gmail.com
##
##Edit Line 115 to change directory path for the file extraction

@load base/files/extract

global ext_map: table[string] of string = {
    		["application/x-dosexec"] = "exe",
		["application/msword"] = "doc",
		["application/x-dmg"] = "dmg",
		["application/x-gzip"] = "gz",
		["application/x-rar"] = "rar",
		["application/x-tar"] = "tar",
		["application/x-xar"] = "pkg",
		["application/x-rpm"] = "rpm",
		["application/x-stuffit"] = "sif",
		["application/x-archive"] = "arch",
		["application/x-arc"] = "arc",
		["application/x-eet"] = "eet",
		["application/x-zoo"] = "zoo",
		["application/x-lz4"] = "lz4",
		["application/x-lrzip"] = "lrz",
		["application/x-lzh"] = "lzh",
		["application/warc"] = "warc",
		["application/x-7z-compressed"] ="7z",
		["application/x-xz"] = "xz",
		["application/x-lha"] = "lha",
		["application/x-arj"] = "arj",
		["application/x-cpio"] = "cpio",
		["application/x-compress"] = "cmp",
		["application/x-lzma"] = "lzm",
		["application/zip"] = "zip",
		["application/vnd.ms-cab-compressed"] = "cab",
		["application/pdf"] = "pdf",
		["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
		["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
		["application/vnd.openxmlformats-officedocument.presentationml.presentation"] ="pptx",
		["application/font-woff"] = "woff",
		["application/x-font-ttf"] = "ttf",
		["application/vnd.ms-fontobject"] = "eot",
		["application/x-font-sfn"] = "sfn",
		["application/vnd.ms-opentype"] = "otf",
		["application/x-mif"] = "mif",
		["application/vnd.font-fontforge-sfd"] = "sfd",
		["audio/mpeg"] = "mp3",
		["audo/m4a"] = "mp4",
		["image/tiff"] = "tiff",
		["image/gif"] = "gif",
		["image/jpeg"] = "jpg",
		["image/x-ms-bmp"] = "bmp",
		["image/x-icon"] = "ico",
		["image/x-cursor"] = "cur",
		["image/vnd.adobe.photoshop"] = "pnd",
		["image/png"] = "png",
		["text/html"] = "html",
		["text/plain"] = "txt",
		["text/json"] = "json",
		["text/rtf"] = "rtf",
		["application/xml"] = "xml",
		["text/rss"] = "rss",
		["application/java-archive"] = "jar",
		["application/x-java-applet"] = "jar",
		["application/x-shockwave-flash"] = "swf",
		["application/pkcs7-signature"] = "p7",
		["application/x-pem"] = "pem",
		["application/x-java-jnlp-file"] = "jnlp",
		["application/vnd.tcpdump.pcap"] = "pcap",
		["text/x-shellscript"] = "sh",
		["text/x-perl"] = "pl",
		["text/x-ruby"] = "rb",
		["text/x-python"] = "py",
		["text/x-awk"] = "awk",
		["text/x-lua"] ="lua",
		["application/javascript"] = "js",
		["text/x-php"] = "php",
		["application/x-executable"] = "xexe",
		["application/x-coredump"] = "core",
		["video/x-flv"] = "flv",
		["video/x-fli"] = "fli",
		["video/x-flc"] = "flc",
		["video/mj2"] = "mj2",
		["video/x-mng"] = "mng",
		["video/x-jng"] = "jng",
		["video/mpeg"] = "mpg",
		["video/mpv"] = "mpv",
		["video/h264"] = "264",
		["video/webm"] = "webm",
		["video/matroska"] = "mkv",
		["vidoe/x-sgi-movie"] = "sgi",
		["video/quicktime"] = "qt",
		["video/mp4"] = "mp4",
		["video/3gpp"] = "3gp",
} &default ="";

global ext: string ;

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	ext = ext_map[meta$mime_type] ;
	}

event file_new(f: fa_file)
	{
	local fname = cat(f$last_active, "-", f$source, "-", f$id, ".", ext);
	f$info$extracted = fname ;
	
	##Edit prefix below to your desired save directory for the exctracted files
	const prefix = "/home/so/extract_files/" &redef;
	fname = build_path_compressed(prefix, fname);

#	local fname = fmt("/home/so/extracted_files/%s-%s-%s.%s", f$last_active, f$source, f$id, ext);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
