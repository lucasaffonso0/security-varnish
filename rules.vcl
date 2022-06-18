import std;
import calmdown;
import vsthrottle;

#LISTA DE BACKENDS
include "varnish/backends.vcl";
#REGRAS DE SEGURANÇA - LUCAS
include "varnish/lucas-security.vcl";

acl purge {
# IPs DE APLICAÇÃO PRECISAM ESTAR DEFINIDOS AQUI
   "127.0.0.1";
}

acl forbidden {
     #"IP AQUI";
}

sub vcl_recv {
    # Block access from these ips
    if (std.ip(req.http.X-Real-IP, "0.0.0.0") ~ forbidden) {
        return (synth(403, "Forbidden"));
    }
    #USER AGENTS BLOQUEADOS POR PADRÃO
    if (req.http.User-Agent ~ "(?i)(sqlmap|CrowdTanglebot|DataForSeoBot|omgili|trendictionbot|MJ12bot|MegaIndex|PetalBot|aspiegel|trendkite-akashic-crawler|AhrefsBot|SemrushBot|Seekport Crawler|DotBot|BLEXBot|crawler)") {

                return (synth(403, "Forbidden"));
    }
}


sub vcl_recv {

# Extracts first IP from header, works with and without CloudFlare
set req.http.X-Actual-IP = regsub(req.http.X-Forwarded-For, "[, ].*$", "");

        #Prevent hammering on wp-login page and users doing excessive searches (2 per second)

if(vsthrottle.is_denied(req.http.X-Actual-IP, 2, 1s) && (req.url ~ "xmlrpc|wp-login.php") && req.http.X-Actual-IP != "45.55.41.71") {
        return (synth(428, "Too Many Requests"));
        }
if(vsthrottle.is_denied(req.http.X-Actual-IP, 4, 1s) && (req.url ~ "\?s\=")) {
        return (synth(428, "Too Many Requests"));
        }

#Prevent users from making excessive POST requests that aren't for admin-ajax
if(vsthrottle.is_denied(req.http.X-Actual-IP, 15, 10s) && ((!req.url ~ "\/wp-admin\/|(xmlrpc|admin-ajax)\.php") && (req.method == "POST"))){
        return (synth(428, "Too Many Requests"));
        }

### Purge
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
           return (synth(405, "This IP is not allowed to send PURGE requests."));
        }
        ban("req.http.host == " + req.http.host +
            " && req.url ~ " + req.url);
        # Throw a synthetic page so the request won't go to the backend.
        return(synth(200, "Ban added"));
    }



#   ESTE MÉTODO NO VARNISH 3 E 4 SÓ FAZ PURGE DA URL EXATA. POR CONTA DISSO O PURGE COMPLETO VIA PLUGIN NÃO
#   ESTAVA FUNCIONANDO. COM BAN É POSSÍVEL USAR EXPRESSÕES PARA INDICAR QUE A URL DEVE CONTER DETERMINADO
#   VALOR
#   if (req.method == "PURGE") {
#      if (!client.ip ~ purge) {
#         return (synth(405, "This IP is not allowed to send PURGE requests."));
#      }
#      return (purge);
#   }

   set req.http.grace = "none";

   ### LISTA DE HOSTS POR PROJETO E DEFINIÇÃO HOST > BACKEND

   include "hosts.vcl";


   ### IP Forward
   if (req.restarts == 0) {
      if (req.http.x-real-ip) {
         set req.http.X-Forwarded-For = req.http.X-Real-IP;
      } else {
         set req.http.X-Forwarded-For = client.ip;
      }
   }

   ### Do not cache data that is likely to be user-specific
   if (req.http.Authorization) {
      /* Not cacheable by default */
      return (pass);
   }


#    if (req.url ~ "admin-ajax.php") {
#      return (synth(404, "Not found"));
#    }

#   if (req.url ~ "xmlrpc.php") {
 #     return (synth(404, "Not found"));
  # }

   #if (req.url ~ "/.git") {
    #  return (synth(404, "Not found"));
#   }

   ### Handle recognized HTTP methods and cache GET and HEAD

   if (req.method != "GET" &&
   req.method != "HEAD" &&
   req.method != "PUT" &&
   req.method != "POST" &&
   req.method != "TRACE" &&
   req.method != "OPTIONS" &&
   req.method != "DELETE") {
      /* Non-RFC2616 or CONNECT which is weird. */
      return (pipe);
   }

   if (req.method != "GET" && req.method != "HEAD") {
      /* We only deal with GET and HEAD by default */
      return (pass);
   }

   #VERIFICA HEADER PARA REGRAS DE CACHE CUSTOMIZADA POR HOST
   if (req.http.WP-X-Cache-Skip == "1") {
       return (pass);
   }
   #Ignora arquivos estáticos
   #if (req.url ~ "\.(css|js|png|gif|jp(e?)g)|swf|ico") {
   #   return (pass);
   #}

   # Some generic URL manipulation, useful for all templates that follow
   # First remove the Google Analytics added parameters, useless for our backend
   if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
      set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
      set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
      set req.url = regsub(req.url, "\?&", "?");
      set req.url = regsub(req.url, "\?$", "");
   }

   # Strip hash, server doesn't need it.
   if (req.url ~ "\#") {
      set req.url = regsub(req.url, "\#.*$", "");
   }

   # Strip a trailing ? if it exists
    if (req.url ~ "\?$") {
       set req.url = regsub(req.url, "\?$", "");
    }

   ### Prevent cache in specific areas
   if (req.http.cookie ~ "wordpress_logged_in_") {
      return (pass);
   }

   ### Prevent cache in specific areas protect
   if (req.http.cookie ~ "wp-postpass") {
      return (pass);
   }

  #prevent cache for ajax requests (elementor)
  if (req.http.X-Requested-With == "XMLHttpRequest") {
     return(pass);
  }
   # Pass through the WooCommerce dynamic pages
   if (req.url ~ "^/(/en/detalhes-da-reserva*|/detalhes-da-reserva*|balancetes-2020/|lista-de-orcamento/*|listas-de-casamentos/*|loja/*|wishlist|cart|carrinho|minha-conta/*|my-account/*|checkout|finalizar-compra|wc-api/*|addons|logout|lost-password|/en/produto/*|/produto/*|product/*|login*|register*|seu-perfil*|lostpassword*|resetpass*)" ||
      req.url ~ "wp-(login|admin|cron)" ||
      req.url ~ "preview=true" ||
      req.url ~ "elementor-preview" ||
      req.url ~ "xmlrpc.php" ||
      req.url ~ "sitemap-news.xml" ||
      req.url ~ "server-status" ) {
      return (pass);
   }

   # Pass through the WooCommerce add to cart
   if (req.url ~ "\?add-to-cart=" ) {
      return (pass);
   }

   # Pass through the WooCommerce API
   if (req.url ~ "\?wc-api=" ) {
      return (pass);
   }

  if (req.http.host ~ "(?)intranet.fecomercio-al.com.br") {
     return(pass);
   }
   if (req.http.cookie) {
      # Unset Cookies except for WordPress admin and WooCommerce pages
      if (!(req.url ~ "(/en/detalhes-da-reserva*|/detalhes-da-reserva*|balancetes-2020/|lista-de-orcamento/*|listas-de-casamentos/*|loja/*|wp-login|wp-admin|admin-ajax*|wishlist|cart|carrinho|minha-conta/*|my-account/*|wc-api*|checkout|finalizar-compra|addons|logout|lost-password|/en/produto/*|/produto/*|product/*|login*|register*|seu-perfil*|lostpassword*|resetpass*)")) {
         unset req.http.cookie;
      }
   }

   return (hash);
}
sub vcl_hit {

    if (obj.ttl >= 0s) {
        # normal hit
        return (deliver);
    }
    # We have no fresh fish. Lets look at the stale ones.
    if (std.healthy(req.backend_hint)) {
        # Backend is healthy. Limit age to 10s.
        if (obj.ttl + 10s > 0s) {
            set req.http.grace = "normal(limited)";
            return (deliver);
        } else {
            # No candidate for grace. Fetch a fresh object.
            return(miss);
        }
    } else {
        # backend is sick - use full grace
        if (obj.ttl + obj.grace > 0s) {
            set req.http.grace = "full";
            return (deliver);
        } else {
            # no graced object.
            return (miss);
        }
    }
}

sub vcl_backend_response {
  # if (beresp.http.Content-Type ~ "text/html") {
  #     unset beresp.http.Cache-Control;
  #     set beresp.http.Cache-Control = "no-cache, max-age=0";
  #     set beresp.ttl = 120s;
  #     set beresp.uncacheable = true;
  #     return (deliver);
  #  }


   #VERIFICA HEADER PARA REGRAS DE CACHE CUSTOMIZADA POR HOST
   if (beresp.http.WP-X-Cache-Skip == "1") {
       set beresp.ttl = 120s;
       set beresp.uncacheable = true;
       return (deliver);
   }

   # Enable Saint mode
   # set beresp.grace = 30m;

   unset beresp.http.Vary;
   # Unset Cookies except for WordPress admin and WooCommerce pages
   #if ( (!(bereq.url ~ "(wp-(login|admin)|cart|my-account/*|wc-api*|checkout|addons|logout|lost-password|product/*|login*|register*|seu-perfil*|lostpassword*|resetpass*)")) || (bereq.method == "GET") ) {
   if ( (!(bereq.url ~ "(wp-(login|admin)|wp-admin/admin-ajax.php|/en/detalhes-da-reserva*|/detalhes-da-reserva*|balancetes-2020/|lista-de-orcamento/*|listas-de-casamentos/*|loja/*|wishlist|cart|carrinho|minha-conta/*|my-account/*|wc-api*|checkout|finalizar-compra|addons|logout|lost-password|/en/produto/*|/produto/*|product/*|login*|register*|seu-perfil*|lostpassword*|resetpass*)")) && (bereq.method == "GET" || bereq.method == "HEAD") ) {
      unset beresp.http.set-cookie;
      set beresp.ttl = 24h;
   }

   #CUSTOM TTL FOR SPECIFIC AREAS
   if (bereq.url ~ "mais-lidas" || bereq.url == "/categorias/noticias/") {
      unset beresp.http.set-cookie;
      set beresp.ttl = 15m;
   }

   ##ARQUIVOS ESTÁTICOS NÃO ATIVAM ESI
   if (bereq.url !~ "\.(css|js|png|gif|jp(e?)g)|rar|zip|git|swf|woff|ico|pdf|svg") {

      set beresp.http.X-ESI = "enabled";
      set beresp.do_esi = true;
   }
   ##CONTEÚDO ESI TEM TTL REDUZIDO
   if (bereq.url ~ "\?esi=1" ) {

      set beresp.ttl = 30s;
   }

   set beresp.grace = 36h;

   # This block will make sure that if the upstream returns a 5xx, but we have the response in the cache (even if it's expired),
   # we fall back to the cached value (until the grace period is over).
   # Reference: https://blog.markvincze.com/how-to-gracefully-fall-back-to-cache-on-5xx-responses-with-varnish/
   if (beresp.status == 429 || beresp.status == 500 || beresp.status == 502 || beresp.status == 503 || beresp.status == 504)
   {
       # This check is important. If is_bgfetch is true, it means that we've found and returned the cached object to the client,
       # and triggered an asynchoronus background update. In that case, if it was a 5xx, we have to abandon, otherwise the previously cached object
       # would be erased from the cache (even if we set uncacheable to true).
       if (bereq.is_bgfetch)
       {
           return (abandon);
       }

       # We should never cache a 5xx response.
       set beresp.uncacheable = true;
   }

   return (deliver);
}

sub vcl_deliver {
   set resp.http.grace = req.http.grace;

   if (obj.hits > 0) {
      set resp.http.X-Cache = "HIT";
      set resp.http.X-Cache-Hits = obj.hits;
   } else {
      set resp.http.X-Cache = "MISS";
   }

   # Remove some headers: PHP version
   unset resp.http.X-Powered-By;

   # Remove some headers: Apache version & OS
   unset resp.http.Server;
   unset resp.http.X-Drupal-Cache;
   unset resp.http.X-Varnish;
   unset resp.http.Via;
   unset resp.http.Link;
}
