// Copyright 2013 hee authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package cmd ...
package cmd

import (
	"github.com/skOak/hee/cmd/commands"
	_ "github.com/skOak/hee/cmd/commands/api"
	_ "github.com/skOak/hee/cmd/commands/bale"
	_ "github.com/skOak/hee/cmd/commands/beefix"
	_ "github.com/skOak/hee/cmd/commands/dlv"
	_ "github.com/skOak/hee/cmd/commands/dockerize"
	_ "github.com/skOak/hee/cmd/commands/generate"
	_ "github.com/skOak/hee/cmd/commands/hprose"
	_ "github.com/skOak/hee/cmd/commands/migrate"
	_ "github.com/skOak/hee/cmd/commands/new"
	_ "github.com/skOak/hee/cmd/commands/pack"
	_ "github.com/skOak/hee/cmd/commands/rs"
	_ "github.com/skOak/hee/cmd/commands/run"
	_ "github.com/skOak/hee/cmd/commands/server"
	_ "github.com/skOak/hee/cmd/commands/version"
	"github.com/skOak/hee/utils"
)

func IfGenerateDocs(name string, args []string) bool {
	if name != "generate" {
		return false
	}
	for _, a := range args {
		if a == "docs" {
			return true
		}
	}
	return false
}

var usageTemplate = `{{"USAGE" | headline}}
    {{"hee command [arguments]" | bold}}

{{"AVAILABLE COMMANDS" | headline}}
{{range .}}{{if .Runnable}}
    {{.Name | printf "%-11s" | bold}} {{.Short}}{{end}}{{end}}

Use {{"hee help [command]" | bold}} for more information about a command.

{{"ADDITIONAL HELP TOPICS" | headline}}
{{range .}}{{if not .Runnable}}
    {{.Name | printf "%-11s"}} {{.Short}}{{end}}{{end}}

Use {{"hee help [topic]" | bold}} for more information about that topic.
`

var helpTemplate = `{{"USAGE" | headline}}
  {{.UsageLine | printf "hee %s" | bold}}
{{if .Options}}{{endline}}{{"OPTIONS" | headline}}{{range $k,$v := .Options}}
  {{$k | printf "-%s" | bold}}
      {{$v}}
  {{end}}{{end}}
{{"DESCRIPTION" | headline}}
  {{tmpltostr .Long . | trim}}
`

var ErrorTemplate = `hee: %s.
Use {{"hee help" | bold}} for more information.
`

func Usage() {
	utils.Tmpl(usageTemplate, commands.AvailableCommands)
}

func Help(args []string) {
	if len(args) == 0 {
		Usage()
	}
	if len(args) != 1 {
		utils.PrintErrorAndExit("Too many arguments", ErrorTemplate)
	}

	arg := args[0]

	for _, cmd := range commands.AvailableCommands {
		if cmd.Name() == arg {
			utils.Tmpl(helpTemplate, cmd)
			return
		}
	}
	utils.PrintErrorAndExit("Unknown help topic", ErrorTemplate)
}
