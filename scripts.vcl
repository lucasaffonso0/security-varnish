sub bloqueado {
        return (synth(403, "Forbidden"));
}

sub vcl_recv {

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ "(?i)<?(java|vb)?script>?.*<.+\/script>?") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ "(?i)(<|\%3C)?(java|vb)?script(>|\%3E).*(<|\%3C).*\/script(>|\%3E)?") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ "(?i)(java|vb)?script:") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ "(?i)\(.*javascript.*\)") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ "(?i)\(.*vbscript.*\)") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar script javascript(XSS) na URL
    if (req.url ~ ":?.*url\(") {
        call bloqueado;
    }
        #SSI Injection
        if (req.url ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*(!|%21)--(\s|%20|\t|%09|\+)*(#|%23)(\s|%20|\t|%09|\+)*(e(cho|xec)|printenv|include|cmd)") {
                call bloqueado;
        }

        if (req.http.X-VFW-Body) {
                # SSI Injection
                if (req.http.X-VFW-Body ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*(!|%21)--(\s|%20|\t|%09|\+)*(#|%23)(\s|%20|\t|%09|\+)*(e(cho|xec)|printenv|include|cmd)") {
                        call bloqueado;
                }
        }
    if (!req.http.X-VSF-Static) {
        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)((\s|%20|\t|%09|\+)*P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(>|%3E)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(:|%3A)[^&](\(|%28)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(J|%[46]A)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(L|%[46]C)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(D|%[46]4)") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((I|%[46]9)(\s|%20|\t|%09|\+)*)?(F|%[46]6)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(E|%[46]5)((S|%[57]3)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4))?") {
                call bloqueado;
        }

        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(G|%[46]7)") {
                call bloqueado;
        }


        if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(F|%[46]6)(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(M|%[46]D)") {
                call bloqueado;
        }


        if (req.http.X-VSF-Body) {
            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)((\s|%20|\t|%09|\+)*P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(>|%3E)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(:|%3A)[^&](\(|%28)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(J|%[46]A)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(L|%[46]C)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(D|%[46]4)") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((I|%[46]9)(\s|%20|\t|%09|\+)*)?(F|%[46]6)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(E|%[46]5)((S|%[57]3)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4))?") {
                call bloqueado;
            }

            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(G|%[46]7)") {
                call bloqueado;
            }


            if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(F|%[46]6)(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(M|%[46]D)") {
                call bloqueado;
            }

        }
    }
#Bloquear encoder char()
        if (req.url ~ "(?i)char\(.*\)") {
                call bloqueado;
        }

        #######SQL INJECTION#######
        #Verifica se alguém tenta usar a instrução SQL no URL: ORDER BY
        if (req.url ~ "(?i).+ORDER.+BY" && req.url !~ "(?i)google-site-kit" && req.url !~ "(?i)wc-analytics") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: UNION SELECT
        if (req.url ~ "(?i).+UNION.+SELECT") {
                call bloqueado;
        }
        #Verifica se alguém tenta usar a instrução SQL no URL: AND SLEEP
        if (req.url ~ "(?i).+AND.+SLEEP") {
                call bloqueado;
        }
        #Verifica se alguém tenta usar a instrução SQL no URL: SELECT FROM
        if (req.url ~ "(?i).+SELECT.+FROM" && req.url !~ "(?i)selective_ajax") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: UNION SELECT
        if (req.url ~ "(?i).+UNION.+(.*)ELECT") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: UPDATE SET
        if (req.url ~ "(?i).+UPDATE.+SET.+WHERE.") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: INSERT INTO
        if (req.url ~ "(?i).+INSERT.+INTO") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: DELETE FROM
        if (req.url ~ "(?i).+DELETE.+FROM") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: ASCII SELECT
        if (req.url ~ "(?i).+ASCII.+SELECT") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: DROP TABLE
        if (req.url ~ "(?i).+DROP.+TABLE") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: DROP DATABASE
        if (req.url ~ "(?i).+DROP.+DATABASE") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: SELECT VERSION
        if (req.url ~ "(?i).+SELECT.+VERSION") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: SHOW CURDATE / CURTIME
        if (req.url ~ "(?i).+SHOW.+CUR(DATE|TIME)") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: SELECT SUBSTR
        if (req.url ~ "(?i).+SELECT.+SUBSTR") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: SELECT INSTR
        if (req.url ~ "(?i).+SELECT.+INSTR") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: SHOW CHARACTER SET
        if (req.url ~ "(?i).+SHOW.+CHARACTER.+SET") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: BULK INSERT
        if (req.url ~ "(?i).+BULK.+INSERT") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: INSERT VALUES
        if (req.url ~ "(?i).+INSERT.+VALUES") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL no URL: MySQL Comments / * * /
        if (req.url ~ "(?i).+\%2F\%2A.+\%2A\%2F") {
                call bloqueado;
        }

        #Verifica se alguém tenta usar a instrução SQL na URL: SELEC CONCAT
        if (req.url ~ "(?i).+SELECT.+CONCAT") {
                call bloqueado;
        }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: wget
    if (req.url ~ "(=|;|&&|%7C%7C)wget(\s|\%20).+") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: curl
    if (req.url ~ "(=|;|&&|%7C%7C)curl(\s|\%20).+") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: echo
    if (req.url ~ "(=|;|&&|%7C%7C)echo(\s|\%20).+") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: cat
    if (req.url ~ "(=|;|&&|%7C%7C)cat(\s|\%20).+") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: cmd.ex
    if (req.url ~ "(=|;|&&|%7C%7C)cmd.exe(\s|\%20).+") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar um nome de comando comum na URL: netcat
    if (req.url ~ "(=|;|&&)nc(.exe)?(\s|\%20).+(\-(l|p)?)?") {
        call bloqueado;
    }

    #Verifica se alguém tenta injetar algum comando unix na URL: whoami/who/uptime/df
    if (req.url ~ "(=|;|&&)(whoami|who|uptime).*") {
        call bloqueado;
    }

    #Verifica se alguém tenta redirecionar a saída do comando na URL:  /dev/null
    if (req.url ~ "(>|%3E|-o)+" && req.url ~ "/dev/null") {
        call bloqueado;
    }

}
