/*
 * Copyright 2020 Huawei Technologies Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	_ "lcmcontroller/config"
	"lcmcontroller/controllers"
	_ "lcmcontroller/controllers"
	_ "lcmcontroller/models"
	_ "lcmcontroller/routers"
	"lcmcontroller/util"
	"net"
	"net/http"
	"strconv"
)

type rateLimiter struct {
	generalLimiter *limiter.Limiter
}

// Start lcmcontroller application
func main() {
	r := &rateLimiter{}
	rate, err := limiter.NewRateFromFormatted("200-S")
	r.generalLimiter = limiter.New(memory.NewStore(), rate)

	beego.InsertFilter("/*", beego.BeforeRouter, func(c *context.Context) {
		rateLimit(r, c)
	}, true)

	beego.ErrorHandler("429", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Too Many Requests"))
		return
	})

	tlsConf, err := util.TLSConfig("HTTPSCertFile")
	if err != nil {
		log.Error("failed to config tls for beego")
		return
	}

	beego.BeeApp.Server.TLSConfig = tlsConf
	beego.ErrorController(&controllers.ErrorController{})
	beego.Run()
}

func rateLimit(r *rateLimiter, ctx *context.Context) {
	var (
		limiterCtx limiter.Context
		ip         net.IP
		err        error
		req        = ctx.Request
	)

	ip = r.generalLimiter.GetIP(req)
	limiterCtx, err = r.generalLimiter.Get(req.Context(), ip.String())
	if err != nil {
		ctx.Abort(http.StatusInternalServerError, err.Error())
		return
	}

	h := ctx.ResponseWriter.Header()
	h.Add("X-RateLimit-Limit", strconv.FormatInt(limiterCtx.Limit, 10))
	h.Add("X-RateLimit-Remaining", strconv.FormatInt(limiterCtx.Remaining, 10))
	h.Add("X-RateLimit-Reset", strconv.FormatInt(limiterCtx.Reset, 10))

	if limiterCtx.Reached {
		log.Info("Too Many Requests from %s on %s", ip, ctx.Input.URL())
		ctx.Abort(http.StatusTooManyRequests, "429")
		return
	}
}
