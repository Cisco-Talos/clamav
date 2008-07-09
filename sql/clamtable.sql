DROP TABLE IF EXISTS disasm;
DROP TABLE IF EXISTS icons;
DROP TABLE IF EXISTS exports;
DROP TABLE IF EXISTS imports;
DROP TABLE IF EXISTS sections;
DROP TABLE IF EXISTS dstrib10;
DROP TABLE IF EXISTS pes;

CREATE TABLE `pes` (
  `id` bigint(20) unsigned NOT NULL auto_increment,
  `fname` text NOT NULL,
  `fsize` int(10) unsigned NOT NULL,
  `peplus` tinyint(1) unsigned NOT NULL,
  `arch` smallint(5) unsigned NOT NULL,
  `sizeofopth` smallint(5) unsigned NOT NULL,
  `att_norelocs` tinyint(1) unsigned NOT NULL,
  `att_executable` tinyint(1) unsigned NOT NULL,
  `att_nolines` tinyint(1) unsigned NOT NULL,
  `att_nosymbs` tinyint(1) unsigned NOT NULL,
  `att_64bit` tinyint(1) unsigned NOT NULL,
  `att_32bit` tinyint(1) unsigned NOT NULL,
  `att_nodebug` tinyint(1) unsigned NOT NULL,
  `att_system` tinyint(1) unsigned NOT NULL,
  `att_dll` tinyint(1) unsigned NOT NULL,
  `att_unicpu` tinyint(1) unsigned NOT NULL,
  `symbols` int(10) unsigned NOT NULL,
  `sizeofcode` int(10) unsigned NOT NULL,
  `sizeofidata` int(10) unsigned NOT NULL,
  `sizeofudata` int(10) unsigned NOT NULL,
  `sizeofimg` int(10) unsigned NOT NULL,
  `sizeofhdr` int(10) unsigned NOT NULL,
  `baseofcode` int(10) unsigned NOT NULL,
  `baseofdata` int(10) unsigned NOT NULL, 
  `imagebase` bigint(20) unsigned NOT NULL,
  `ep` int(10) unsigned NOT NULL,
  `sections` tinyint(3) unsigned NOT NULL,
  `ep_section` tinyint(2) unsigned NOT NULL,
  `valign` int(10) unsigned NOT NULL,
  `falign` int(10) unsigned NOT NULL,
  `checksum_ok` tinyint(1) signed NOT NULL,
  `subsys` smallint(5) unsigned NOT NULL,
  `dll_relocable` tinyint(1) unsigned NOT NULL,
  `dll_integrity` tinyint(1) unsigned NOT NULL,
  `dll_dep` tinyint(1) unsigned NOT NULL,
  `dll_noiso` tinyint(1) unsigned NOT NULL,
  `dll_noseh` tinyint(1) unsigned NOT NULL,
  `dll_nobind` tinyint(1) unsigned NOT NULL,
  `dll_wdm` tinyint(1) unsigned NOT NULL,
  `dll_ts` tinyint(1) unsigned NOT NULL,
  `imports` int(10) unsigned NOT NULL,
  `exports` int(10) unsigned NOT NULL,
  `rs_total` int(10) unsigned NOT NULL,
  `rs_other` int(10) unsigned NOT NULL,
  `rs_cursor` int(10) unsigned NOT NULL,
  `rs_bitmap` int(10) unsigned NOT NULL,
  `rs_icon` int(10) unsigned NOT NULL,
  `rs_menu` int(10) unsigned NOT NULL,
  `rs_dialog` int(10) unsigned NOT NULL,
  `rs_string` int(10) unsigned NOT NULL,
  `rs_fontdir` int(10) unsigned NOT NULL,
  `rs_font` int(10) unsigned NOT NULL,
  `rs_accel` int(10) unsigned NOT NULL,
  `rs_rc` int(10) unsigned NOT NULL,
  `rs_msgtable` int(10) unsigned NOT NULL,
  `rs_gcursor` int(10) unsigned NOT NULL,
  `rs_gicon` int(10) unsigned NOT NULL,
  `rs_version` int(10) unsigned NOT NULL,
  `rs_anic` int(10) unsigned NOT NULL,
  `rs_anii` int(10) unsigned NOT NULL,
  `rs_html` int(10) unsigned NOT NULL,
  `rs_manifest` int(10) unsigned NOT NULL,
  `signature_ok` tinyint(1) unsigned NOT NULL, -- TBD
  `relocs` int(10) unsigned NOT NULL,
  `have_debug` tinyint(1) unsigned NOT NULL,
  `have_tls` tinyint(1) unsigned NOT NULL,
  `have_bounds` tinyint(1) unsigned NOT NULL,
  `have_iat` tinyint(1) unsigned NOT NULL,
  `have_delay` tinyint(1) unsigned NOT NULL,
  `have_com` tinyint(1) unsigned NOT NULL,
  `overlays` int(10) unsigned NOT NULL,
  `md5` char(32) NOT NULL,
  `entropy` double NOT NULL,
  `datasource` CHAR(255) NULL,
  `infected` tinyint(1) NULL,
  `scandate` datetime NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `dstrib10` (
  `ref` bigint(20) unsigned NOT NULL,
  `snum` tinyint(3) NOT NULL,
  `type` enum ('glob', 'off0', 'off1', 'off2', 'off3') NOT NULL,
  `0_value` int(10) unsigned NOT NULL,
  `0_pcnt` double unsigned NOT NULL,
  `1_value` int(10) unsigned NOT NULL,
  `1_pcnt` double unsigned NOT NULL,
  `2_value` int(10) unsigned NOT NULL,
  `2_pcnt` double unsigned NOT NULL,
  `3_value` int(10) unsigned NOT NULL,
  `3_pcnt` double unsigned NOT NULL,
  `4_value` int(10) unsigned NOT NULL,
  `4_pcnt` double unsigned NOT NULL,
  `5_value` int(10) unsigned NOT NULL,
  `5_pcnt` double unsigned NOT NULL,
  `6_value` int(10) unsigned NOT NULL,
  `6_pcnt` double unsigned NOT NULL,
  `7_value` int(10) unsigned NOT NULL,
  `7_pcnt` double unsigned NOT NULL,
  `8_value` int(10) unsigned NOT NULL,
  `8_pcnt` double unsigned NOT NULL,
  `9_value` int(10) unsigned NOT NULL,
  `9_pcnt` double unsigned NOT NULL,
  UNIQUE KEY `uniq` (`ref`,`snum`,`type`),
  KEY `ref` (`ref`),
  CONSTRAINT `dstrib10` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `sections` (
  `ref` bigint(20) unsigned NOT NULL,
  `snum` tinyint(3) unsigned NOT NULL,
  `name` char(8) NOT NULL,
  `vsz` int(10) unsigned NOT NULL,
  `rva` int(10) unsigned NOT NULL,
  `rsz` int(10) unsigned NOT NULL,
  `raw` int(10) unsigned NOT NULL,
  `att_code` tinyint(1) unsigned NOT NULL,
  `att_init` tinyint(1) unsigned NOT NULL,
  `att_uninit` tinyint(1) unsigned NOT NULL,
  `att_discard` tinyint(1) unsigned NOT NULL,
  `att_nocache` tinyint(1) unsigned NOT NULL,
  `att_nopage` tinyint(1) unsigned NOT NULL,
  `att_share` tinyint(1) unsigned NOT NULL,
  `att_r` tinyint(1) unsigned NOT NULL,
  `att_w` tinyint(1) unsigned NOT NULL,
  `att_x` tinyint(1) unsigned NOT NULL,
  `md5` char(32) NOT NULL,
  `entropy` double NOT NULL,
  UNIQUE KEY `uniq` (`ref`,`snum`),
  KEY `ref` (`ref`),
  CONSTRAINT `sections` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `imports` (
  `ref` bigint(20) unsigned NOT NULL,
  `lib` char(255) NOT NULL,
  `ord` smallint unsigned NOT NULL,
  `fun` char(255) NOT NULL,
  KEY `ref` (`ref`),
  CONSTRAINT `imports` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `exports` (
  `ref` bigint(20) unsigned NOT NULL,
  `ord` smallint unsigned NOT NULL,
  `fun` char(255) NOT NULL,
  KEY `ref` (`ref`),
  CONSTRAINT `exports` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `disasm` (
  `ref` bigint(20) unsigned NOT NULL,
  `did` bigint(20) unsigned NOT NULL auto_increment,
  `op` char(100) NOT NULL,
  PRIMARY KEY  (`did`),
  KEY `ref` (`ref`),
  CONSTRAINT `disasm` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `icons` (
  `ref` bigint(20) unsigned NOT NULL,
  `hash` char(32) NOT NULL,
  KEY `ref` (`ref`),
  CONSTRAINT `icons` FOREIGN KEY (`ref`) REFERENCES `pes` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

