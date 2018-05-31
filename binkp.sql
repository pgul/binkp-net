CREATE TABLE IF NOT EXISTS `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `node` char(16) NOT NULL,
  `passwd` char(16) NOT NULL,
  `reset_freq` float unsigned NOT NULL DEFAULT 0,
  `reset_last` int unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node` (`node`)
);
CREATE TABLE IF NOT EXISTS `hosts` (
  `id` int unsigned NOT NULL,
  `host` char(64) DEFAULT NULL,
  `port` smallint unsigned DEFAULT NULL,
  UNIQUE (`id`,`host`,`port`),
  KEY (`id`),
  KEY (`host`)
);
