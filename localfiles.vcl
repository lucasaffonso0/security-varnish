sub vcl_recv {
        #Verifica se alguém tenta acessar arquivos comuns de /etc/
        if (req.url ~ "/etc/(passwd(\-)?|(g)?shadow(\-)?|motd|group(\-)?)") {
                return (synth(403, "Forbidden"));
        }
        #Verifica se alguem tenta acessar parametro vulneravel do Advanced Managet
        if (req.url ~ "(?i)/?aam-media=") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguem tenta acessar parametro vulneravel do Redux Framework
        if (req.url ~ "(?i).*redux.*v1.*templates.*") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos de logs
        if (req.url ~ "((?i)log.txt|logs.txt|readme.txt|readme.md|php_errorlog|php_error.log)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos maliciosos
        if (req.url ~ "((?i)wp-tmp|wp-feed|wp-vcd|wp-cd)") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguém tenta acessar diretórios comuns em /etc/
        if (req.url ~ "/etc/(apache(2)?|httpd|phpmyadmin|mysql|php(4|5)?)/") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguém tenta acessar /tmp/
        if (req.url ~ "/tmp/") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguém tenta acessar diretórios comuns em /var/
        if (req.url ~ "/var/(log|backups|mail|www)/") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguém tenta acessar arquivos comuns de /proc/
        if (req.url ~ "(?i)/proc/(self/environ|cmdline|cpuinfo|mounts|mdstat|partitions|version(_signature)?|uptime)") {
                return (synth(403, "Forbidden"));
        }

        #Verifica se alguém tenta uma travessia de diretório
        if (req.url ~ "\.(\.)?/\.(\.)?/\.(\.)?") {
                return (synth(403, "Forbidden"));
        }

}
