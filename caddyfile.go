package k8singress

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("k8s_ingress", parseGlobalOption)
}

// parseGlobalOption parses the k8s_ingress global option block.
//
// Example Caddyfile usage (global block):
//
//	{
//	    k8s_ingress {
//	        ingress_class  caddy
//	        server_name    https
//	        security {
//	            waf              off
//	            waf_mode         Detection
//	            security_headers on
//	            inject_real_ip   on
//	        }
//	        redis {
//	            address  redis.redis.svc.cluster.local:6379
//	            password secret   # optional
//	            db       0        # optional
//	        }
//	    }
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(App)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "k8s_ingress",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// UnmarshalCaddyfile reads the k8s_ingress block.
func (a *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "ingress_class":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.IngressClass = d.Val()

			case "server_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.ServerName = d.Val()

			case "http_server_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.HTTPServerName = d.Val()

			case "admin_api":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.AdminAPI = d.Val()

			case "security":
				if err := a.parseSecurityBlock(d); err != nil {
					return err
				}

			case "redis":
				if err := a.parseRedisBlock(d); err != nil {
					return err
				}

			case "access_log":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.AccessLog = d.Val() == "on"

			case "verbose_logs":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.VerboseLogs = d.Val() == "on"

			default:
				return d.Errf("unknown k8s_ingress option: %s", d.Val())
			}
		}
	}
	return nil
}

func (a *App) parseRedisBlock(d *caddyfile.Dispenser) error {
	a.Redis = new(RedisConfig)
	for d.NextBlock(1) {
		switch d.Val() {
		case "address":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Redis.Address = d.Val()
		case "password":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Redis.Password = d.Val()
		case "db":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var db int
			if _, err := fmt.Sscanf(d.Val(), "%d", &db); err != nil {
				return d.Errf("redis db must be an integer: %s", d.Val())
			}
			a.Redis.DB = db
		default:
			return d.Errf("unknown redis option: %s", d.Val())
		}
	}
	if a.Redis.Address == "" {
		return d.Err("redis block requires an address")
	}
	return nil
}

func (a *App) parseSecurityBlock(d *caddyfile.Dispenser) error {
	for d.NextBlock(1) {
		switch d.Val() {
		case "waf":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Security.WAF = d.Val() == "on"

		case "waf_mode":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Security.WAFMode = d.Val()

		case "security_headers":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Security.SecurityHeaders = d.Val() == "on"

		case "inject_real_ip":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Security.InjectRealIP = d.Val() == "on"

		default:
			return d.Errf("unknown security option: %s", d.Val())
		}
	}
	return nil
}
