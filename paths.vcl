sub vcl_recv {
        #Bloquear passagem de diretório
        if (req.url ~ "(?i)((/|\\)\.{2}|\.{2}(/|\\))") {
                return (synth(403, "Forbidden"));
        }
        #Bloquear passagem de diretório
        if (req.url ~ "(?i)(..%2F..%2F..%2F)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos internos
        if (req.url ~ "(?i)\.log" && req.url !~ "(?i)(pagseguro|humhub)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos internos
        if (req.url ~ "(?i)\.sh" && req.url !~ "(?i)humhub") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos internos
        if (req.url ~ "(?i)\.zip" && req.http.host !~ "(?i)sindacucar-al.com.br") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos internos
        if (req.url ~ "(?i)\.(cvs|svn|git|hg|sql|inc|ini|htaccess|htpasswd|sqlite|mdb|bat|reg|asa|md|yml|env)") {
                return (synth(403, "Forbidden"));
        }

        if (req.url ~ "(?i)\.(c(o(nf(i?g))|s(proj|r)?|dx|er|fg|md)|p(rinter|ass|db|ol|wd)|v(b(proj|s)?|sdisco)|a(s(ax?|cx)|xd)|d(bf?|at|ll|os)|i(d[acq]|n[ci])|ba([kt]|ckup)|res(ources|x)|s(h?tm|ql|ys)|l(icx|nk)|\w{0,5}~|webinfo|ht[rw]|xs[dx]|key|mdb|old)$") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a api do wordpress
        if (req.url ~ "(?i)/(wp/v2/users/)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear parametro vulneravel do woocommerce
        if (req.url ~ "(?i)/(.*wc.*/store.*/products.*/collection-data.*)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos comuns
        if (req.url ~ "(?i)/.*(license.txt|package-lock.json|nginx_status)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso ao xmlrpc em todos os sites menos em gungaporanga
        if (req.url ~ "(?i)/.*xmlrpc.php" && req.http.host !~ "(?i)gungaporanga.com.br") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a diretorios comuns
        if (req.url ~ "(?i)/(etc/|var/|usr/|tmp|bin/|sbin|dev/|mnt|root|proc/)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a diretorios comuns
        if (req.url ~ "(?i)%2F(etc|var|usr|tmp|bin|sbin|dev|mnt|root|proc)%2F") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos comuns
        if (req.url ~ "(?i)(((vim|bash)rc|\.ssh)|authorized_keys|passwd)") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a particoes do windows
        if (req.url ~ "(?i)[a-z]\:\\") {
                return (synth(403, "Forbidden"));
        }

        #Bloquear acesso a arquivos comuns do windows
        if (req.url ~ "(?i)((cmd(32)?|nc|net|telnet|wsh|ftp|nmap)\.exe|\.(db|bat))") {
                return (synth(403, "Forbidden"));
        }

}
