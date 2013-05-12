CREATE TABLE IF NOT EXISTS `users` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `node` char(16) NOT NULL,
  `passwd` char(16) NOT NULL,
  `reset_freq` float NOT NULL,
  `reset_last` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `node` (`node`)
);
CREATE TABLE IF NOT EXISTS `hosts` (
  `id` int(10) unsigned NOT NULL,
  `host` char(64) DEFAULT NULL,
  `port` smallint(5) unsigned DEFAULT NULL,
  UNIQUE (`id`,`host`,`port`),
  KEY (`id`),
  KEY (`host`)
);
