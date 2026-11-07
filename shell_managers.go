package main

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/git-pkgs/managers/definitions"
)

var shellVersionPattern = regexp.MustCompile(`(?i)(?:@|===?|[~^<>]=?|#)[0-9a-z][0-9a-z._+/*-]*$`)

type shellManagerRule struct {
	manager         string
	ecosystem       string
	operation       string
	qualifier       string
	command         []string
	requiresOperand bool
	valueFlags      map[string]bool
}

func newShellAnalyzer(defs []*definitions.Definition) *shellAnalyzer {
	analyzer := &shellAnalyzer{}
	for _, def := range defs {
		for _, operation := range []string{shellOperationInstall, shellOperationAdd, shellOperationUpdate} {
			command, ok := def.Commands[operation]
			if !ok || len(command.Base) == 0 {
				continue
			}
			analyzer.managerRules = append(analyzer.managerRules, shellManagerRule{
				manager:         def.Name,
				ecosystem:       def.Ecosystem,
				operation:       operation,
				command:         append([]string{def.Binary}, command.Base...),
				requiresOperand: shellCommandRequiresOperand(command),
				valueFlags:      shellCommandValueFlags(command),
			})
			for qualifier, base := range command.BaseOverrides {
				analyzer.managerRules = append(analyzer.managerRules, shellManagerRule{
					manager:         def.Name,
					ecosystem:       def.Ecosystem,
					operation:       operation,
					qualifier:       qualifier,
					command:         append([]string{def.Binary}, base...),
					requiresOperand: shellCommandRequiresOperand(command),
					valueFlags:      shellCommandValueFlags(command),
				})
			}
		}
	}
	sort.Slice(analyzer.managerRules, func(i, j int) bool {
		left := analyzer.managerRules[i]
		right := analyzer.managerRules[j]
		if len(left.command) != len(right.command) {
			return len(left.command) > len(right.command)
		}
		leftKey := strings.Join([]string{strings.Join(left.command, "\x00"), left.manager, left.operation, left.qualifier}, "\x00")
		rightKey := strings.Join([]string{strings.Join(right.command, "\x00"), right.manager, right.operation, right.qualifier}, "\x00")
		return leftKey < rightKey
	})
	return analyzer
}

func (a *shellAnalyzer) packageCommandSignal(filePath string, line uint, args []string) (Signal, bool) {
	for _, rule := range a.managerRules {
		if !shellCommandPrefix(args, rule.command) {
			continue
		}
		operands := shellCommandOperands(args[len(rule.command):], rule.valueFlags)
		if rule.requiresOperand && len(operands) == 0 {
			continue
		}
		value := rule.operation
		if rule.qualifier != "" {
			value += ":" + rule.qualifier
		} else if rule.operation == shellOperationAdd {
			if shellCommandDeclaresVersion(args[len(rule.command):]) {
				value += ":version-declared"
			} else {
				value += ":unversioned"
			}
		}
		return Signal{
			Check: checkShellDependency,
			Kind:  shellKindPackageCommand,
			Name:  rule.manager,
			Value: value,
			Path:  filePath,
			Line:  line,
		}, true
	}
	return Signal{}, false
}

func shellCommandRequiresOperand(command definitions.Command) bool {
	for _, argument := range command.Args {
		if argument.Required && !argument.ExtractionOnly {
			return true
		}
	}
	return false
}

func shellCommandValueFlags(command definitions.Command) map[string]bool {
	flags := make(map[string]bool)
	for _, flag := range command.Flags {
		for index, value := range flag.Values {
			if value.Field == "" || value.Join != "" || index == 0 {
				continue
			}
			literal := flag.Values[index-1].Literal
			if literal != "" {
				flags[literal] = true
			}
		}
	}
	return flags
}

func shellCommandOperands(args []string, valueFlags map[string]bool) []string {
	operands := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if valueFlags[argument] {
			index++
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		operands = append(operands, argument)
	}
	return operands
}

func shellCommandPrefix(args, prefix []string) bool {
	if len(args) < len(prefix) {
		return false
	}
	for index := range prefix {
		argument := args[index]
		wanted := prefix[index]
		if index == 0 {
			argument = path.Base(argument)
			wanted = path.Base(wanted)
		}
		if !strings.EqualFold(argument, wanted) {
			return false
		}
	}
	return true
}

func shellCommandDeclaresVersion(args []string) bool {
	for index, argument := range args {
		lower := strings.ToLower(argument)
		if lower == "--version" || lower == "-v" || lower == "--rev" || lower == "--tag" || lower == "--branch" {
			return index+1 < len(args)
		}
		if strings.HasPrefix(argument, "@") {
			if strings.Count(argument, "@") > 1 {
				return true
			}
			continue
		}
		if shellVersionPattern.MatchString(argument) {
			return true
		}
	}
	return false
}
