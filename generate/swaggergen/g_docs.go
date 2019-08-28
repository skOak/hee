// Copyright 2013 bee authors
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

package swaggergen

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v2"

	beeLogger "github.com/skOak/hee/logger"
	bu "github.com/skOak/hee/utils"
	"sort"
)

const (
	ajson  = "application/json"
	axml   = "application/xml"
	aplain = "text/plain"
	ahtml  = "text/html"
	aform  = "multipart/form-data"
)

var pkgCache map[string]struct{} //pkg:controller:function:comments comments: key:value
var controllerComments map[string]string
var importlist map[string]string
var controllerList map[string]map[string]*Item //controllername Paths items
var modelsList map[string]map[string]Schema
var rootapi Swagger
var astPkgs []*ast.Package

// refer to builtin.go
var basicTypes = map[string]string{
	"bool":       "boolean:",
	"uint":       "integer:int32",
	"uint8":      "integer:int32",
	"uint16":     "integer:int32",
	"uint32":     "integer:int32",
	"uint64":     "integer:int64",
	"int":        "integer:int64",
	"int8":       "integer:int32",
	"int16":      "integer:int32",
	"int32":      "integer:int32",
	"int64":      "integer:int64",
	"uintptr":    "integer:int64",
	"float32":    "number:float",
	"float64":    "number:double",
	"string":     "string:",
	"complex64":  "number:float",
	"complex128": "number:double",
	"byte":       "string:byte",
	"rune":       "string:byte",
	// builtin golang objects
	"time.Time":       "string:string",
	"json.RawMessage": "string:byte",
	"interface{}":     "string:byte",
}

var stdlibObject = map[string]string{
	"&{time Time}":       "time.Time",
	"&{json RawMessage}": "json.RawMessage",
}

var routerFuncs = map[string][]string{
	"Handle":  []string{""},
	"POST":    []string{"POST"},
	"GET":     []string{"GET"},
	"DELETE":  []string{"DELETE"},
	"PATCH":   []string{"PATCH"},
	"PUT":     []string{"PUT"},
	"OPTIONS": []string{"OPTIONS"},
	"HEAD":    []string{"HEAD"},
	"Any":     []string{"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS", "DELETE", "CONNECT", "TRACE"},
	//"StaticFile": []string{"StaticFile"},
	//"Static":     []string{"Static"},
	//"StaticFS":   []string{"StaticFS"},
}

func init() {
	pkgCache = make(map[string]struct{})
	controllerComments = make(map[string]string)
	importlist = make(map[string]string)
	controllerList = make(map[string]map[string]*Item)
	modelsList = make(map[string]map[string]Schema)
	astPkgs = make([]*ast.Package, 0)
}

func ParsePackagesFromDir(dirpath string) {
	c := make(chan error)

	go func() {
		filepath.Walk(dirpath, func(fpath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fileInfo.IsDir() {
				return nil
			}

			// 7 is length of 'vendor' (6) + length of file path separator (1)
			// so we skip dir 'vendor' which is directly under dirpath
			if !(len(fpath) == len(dirpath)+7 && strings.HasSuffix(fpath, "vendor")) &&
				!strings.Contains(fpath, "tests") &&
				!(len(fpath) > len(dirpath) && fpath[len(dirpath)+1] == '.') {
				err = parsePackageFromDir(fpath)
				if err != nil {
					// Send the error to through the channel and continue walking
					c <- fmt.Errorf("Error while parsing directory: %s", err.Error())
					return nil
				}
			}
			return nil
		})
		close(c)
	}()

	for err := range c {
		beeLogger.Log.Warnf("%s", err)
	}
}

func parsePackageFromDir(path string) error {
	fileSet := token.NewFileSet()
	folderPkgs, err := parser.ParseDir(fileSet, path, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	if err != nil {
		return err
	}

	for _, v := range folderPkgs {
		astPkgs = append(astPkgs, v)
	}

	return nil
}

func GenerateDocs(curpath string, downdoc bool, dstPath string) {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, filepath.Join(curpath, "service/router.go"), nil, parser.ParseComments)
	if err != nil {
		beeLogger.Log.Fatalf("Error while parsing router.go: %s", err)
	}

	rootapi.Infos = Information{}
	rootapi.SwaggerVersion = "2.0"

	// Analyse API comments
	if f.Comments != nil {
		for _, c := range f.Comments {
			for _, s := range strings.Split(c.Text(), "\n") {
				if strings.HasPrefix(s, "@APIVersion") {
					rootapi.Infos.Version = strings.TrimSpace(s[len("@APIVersion"):])
				} else if strings.HasPrefix(s, "@Title") {
					rootapi.Infos.Title = strings.TrimSpace(s[len("@Title"):])
				} else if strings.HasPrefix(s, "@Description") {
					rootapi.Infos.Description = strings.TrimSpace(s[len("@Description"):])
				} else if strings.HasPrefix(s, "@TermsOfServiceUrl") {
					rootapi.Infos.TermsOfService = strings.TrimSpace(s[len("@TermsOfServiceUrl"):])
				} else if strings.HasPrefix(s, "@Contact") {
					rootapi.Infos.Contact.EMail = strings.TrimSpace(s[len("@Contact"):])
				} else if strings.HasPrefix(s, "@Name") {
					rootapi.Infos.Contact.Name = strings.TrimSpace(s[len("@Name"):])
				} else if strings.HasPrefix(s, "@URL") {
					rootapi.Infos.Contact.URL = strings.TrimSpace(s[len("@URL"):])
				} else if strings.HasPrefix(s, "@LicenseUrl") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &License{URL: strings.TrimSpace(s[len("@LicenseUrl"):])}
					} else {
						rootapi.Infos.License.URL = strings.TrimSpace(s[len("@LicenseUrl"):])
					}
				} else if strings.HasPrefix(s, "@License") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &License{Name: strings.TrimSpace(s[len("@License"):])}
					} else {
						rootapi.Infos.License.Name = strings.TrimSpace(s[len("@License"):])
					}
				} else if strings.HasPrefix(s, "@Schemes") {
					rootapi.Schemes = strings.Split(strings.TrimSpace(s[len("@Schemes"):]), ",")
				} else if strings.HasPrefix(s, "@Host") {
					rootapi.Host = strings.TrimSpace(s[len("@Host"):])
				} else if strings.HasPrefix(s, "@SecurityDefinition") {
					if len(rootapi.SecurityDefinitions) == 0 {
						rootapi.SecurityDefinitions = make(map[string]Security)
					}
					var out Security
					p := getparams(strings.TrimSpace(s[len("@SecurityDefinition"):]))
					if len(p) < 2 {
						beeLogger.Log.Fatalf("Not enough params for security: %d\n", len(p))
					}
					out.Type = p[1]
					switch out.Type {
					case "oauth2":
						if len(p) < 6 {
							beeLogger.Log.Fatalf("Not enough params for oauth2: %d\n", len(p))
						}
						if !(p[3] == "implicit" || p[3] == "password" || p[3] == "application" || p[3] == "accessCode") {
							beeLogger.Log.Fatalf("Unknown flow type: %s. Possible values are `implicit`, `password`, `application` or `accessCode`.\n", p[1])
						}
						out.AuthorizationURL = p[2]
						out.Flow = p[3]
						if len(p)%2 != 0 {
							out.Description = strings.Trim(p[len(p)-1], `" `)
						}
						out.Scopes = make(map[string]string)
						for i := 4; i < len(p)-1; i += 2 {
							out.Scopes[p[i]] = strings.Trim(p[i+1], `" `)
						}
					case "apiKey":
						if len(p) < 4 {
							beeLogger.Log.Fatalf("Not enough params for apiKey: %d\n", len(p))
						}
						if !(p[3] == "header" || p[3] == "query") {
							beeLogger.Log.Fatalf("Unknown in type: %s. Possible values are `query` or `header`.\n", p[4])
						}
						out.Name = p[2]
						out.In = p[3]
						if len(p) > 4 {
							out.Description = strings.Trim(p[4], `" `)
						}
					case "basic":
						if len(p) > 2 {
							out.Description = strings.Trim(p[2], `" `)
						}
					default:
						beeLogger.Log.Fatalf("Unknown security type: %s. Possible values are `oauth2`, `apiKey` or `basic`.\n", p[1])
					}
					rootapi.SecurityDefinitions[p[0]] = out
				} else if strings.HasPrefix(s, "@Security") {
					if len(rootapi.Security) == 0 {
						rootapi.Security = make([]map[string][]string, 0)
					}
					rootapi.Security = append(rootapi.Security, getSecurity(s))
				}
			}
		}
	}
	// Analyse controller mathods in local service package
	analyseControllerPkg(path.Join(curpath, "service"), "", "")
	// Analyse controller package
	for _, im := range f.Imports {
		localName := ""
		if im.Name != nil {
			localName = im.Name.Name
		}
		analyseControllerPkg(path.Join(curpath, "vendor"), localName, im.Path.Value)
	}
	for _, d := range f.Decls {
		switch specDecl := d.(type) {
		case *ast.FuncDecl:
			if specDecl.Name.Name != "router" {
				continue
			}
			for _, l := range specDecl.Body.List {
				switch stmt := l.(type) {
				case *ast.BlockStmt: // { v1:=svr.Group("v1"); v1.GET("version",s.Version); }
					analyseNewGroup("/", stmt, "TOP")
				case *ast.IfStmt:
					analyseNewGroup("/", stmt.Body, "TOP")
				case *ast.ExprStmt: // svr.GET("/captcha", s.GetCaptcha)
					analyseNewRouter("/", stmt.X.(*ast.CallExpr), "TOP")
				case *ast.AssignStmt:
					// won't go here currently
					//beeLogger.Log.Warnf("won't go here currently:%v", stmt.Tok.String())
					continue
					for _, l := range stmt.Rhs {
						if v, ok := l.(*ast.CallExpr); ok {
							// Analyse NewNamespace, it will return version and the subfunction
							if selName := v.Fun.(*ast.SelectorExpr).Sel.String(); selName != "NewNamespace" {
								continue
							}
							version, params := analyseNewNamespace(v)
							if rootapi.BasePath == "" && version != "" {
								rootapi.BasePath = version
							}
							for _, p := range params {
								switch pp := p.(type) {
								case *ast.CallExpr:
									var controllerName string
									if selname := pp.Fun.(*ast.SelectorExpr).Sel.String(); selname == "NSNamespace" {
										s, params := analyseNewNamespace(pp)
										for _, sp := range params {
											switch pp := sp.(type) {
											case *ast.CallExpr:
												if pp.Fun.(*ast.SelectorExpr).Sel.String() == "NSInclude" {
													controllerName = analyseNSInclude(s, pp)
													if v, ok := controllerComments[controllerName]; ok {
														rootapi.Tags = append(rootapi.Tags, Tag{
															Name:        strings.Trim(s, "/"),
															Description: v,
														})
													}
												}
											}
										}
									} else if selname == "NSInclude" {
										controllerName = analyseNSInclude("", pp)
										if v, ok := controllerComments[controllerName]; ok {
											rootapi.Tags = append(rootapi.Tags, Tag{
												Name:        controllerName, // if the NSInclude has no prefix, we use the controllername as the tag
												Description: v,
											})
										}
									}
								}
							}
						}
					}
				default:
					beeLogger.Log.Infof("Unknown statement<%#+v>", stmt)
				}
			}
		}
	}
	os.Mkdir(path.Join(dstPath, "swagger"), 0755)
	fd, err := os.Create(path.Join(dstPath, "swagger", "swagger.json"))
	if err != nil {
		panic(err)
	}
	fdyml, err := os.Create(path.Join(dstPath, "swagger", "swagger.yml"))
	if err != nil {
		panic(err)
	}
	defer fdyml.Close()
	defer fd.Close()
	dt, err := json.MarshalIndent(rootapi, "", "    ")
	dtyml, erryml := yaml.Marshal(rootapi)
	if err != nil || erryml != nil {
		panic(err)
	}
	_, err = fd.Write(dt)
	_, erryml = fdyml.Write(dtyml)
	if err != nil || erryml != nil {
		panic(err)
	}

	if downdoc {
		if _, err := os.Stat(path.Join(dstPath, "swagger", "index.html")); err != nil {
			if os.IsNotExist(err) {
				os.Chdir(dstPath)
				bu.DownloadFromURL(bu.Swaggerlink, "swagger.zip")
				beeLogger.Log.Warnf("unzipAndDelete:%v", bu.UnzipAndDelete("swagger.zip"))
			}
		}
	}
}

func routerMethods(fname string) (methods []string, ok bool) {
	methods, ok = routerFuncs[fname]
	return
}

func analyseNewGroup(baseUrl string, cg *ast.BlockStmt, stag string) {
	if baseUrl == "" {
		baseUrl = "/"
	}
	_, err := url.ParseRequestURI(baseUrl)
	if err != nil {
		beeLogger.Log.Fatalf("analyseNewGroup:baseUrl<%s> is invalid", baseUrl)
		return
	}
	if cg == nil {
		return
	}

	currPath := ""
	currGName := ""
	currTag := stag // 默认用传入的tag
	for _, stmt := range cg.List {
		switch v := stmt.(type) {
		case *ast.AssignStmt: // v1 := svr.Group("v1")
			for _, r := range v.Rhs {
				if kr, ok := r.(*ast.CallExpr); ok {
					if selName := kr.Fun.(*ast.SelectorExpr).Sel.String(); selName != "Group" {
						beeLogger.Log.Fatalf("analyseNewGroup:assignment<%v> inside {} is not Group creation", stmt)
						return
					}
					if currPath != "" || currGName != "" {
						beeLogger.Log.Fatalf("analyseNewGroup:assignment<%v> inside {} is the second Group creation", stmt)
						return
					}
					currPath = strings.Trim(kr.Args[0].(*ast.BasicLit).Value, "\"")
					currGName = fmt.Sprintln(kr.Fun.(*ast.SelectorExpr).X)
				} else {
					beeLogger.Log.Fatalf("analyseNewGroup:assignment<%v> inside {} is not Group creation", stmt)
					return
				}
			}
		case *ast.DeclStmt: // var v1 = svr.Group("v1") // GROUP_NAME
			for _, s := range v.Decl.(*ast.GenDecl).Specs {
				if ks, ok := s.(*ast.ValueSpec); ok {
					if kks, ok := ks.Values[0].(*ast.CallExpr); ok {
						if selName := kks.Fun.(*ast.SelectorExpr).Sel.String(); selName != "Group" {
							beeLogger.Log.Fatalf("analyseNewGroup:assignment<%v> inside {} is not Group creation", stmt)
							return
						}
						if currPath != "" || currGName != "" {
							beeLogger.Log.Fatalf("analyseNewGroup:assignment<%v> inside {} is the second Group creation", stmt)
							return
						}
						currPath = strings.Trim(kks.Args[0].(*ast.BasicLit).Value, "\"")
						currGName = fmt.Sprintln(kks.Fun.(*ast.SelectorExpr).X)
						currTag = ks.Comment.Text() // 覆盖默认的tag信息
					} else {
						beeLogger.Log.Fatalf("analyseNewGroup:declaration<%v> inside {} is not Group creation", stmt)
						return
					}
				} else {
					beeLogger.Log.Fatalf("analyseNewGroup:declaration<%v> inside {} is not Group creation", stmt)
					return
				}
			}
		case *ast.ExprStmt: // v1.GET("version", s.Version)
			analyseNewRouter(baseUrl+currPath, v.X.(*ast.CallExpr), currTag)
		case *ast.BlockStmt: // { children group inside }
			analyseNewGroup(baseUrl+currPath, v, currTag)
		case *ast.IfStmt:
			analyseNewGroup(baseUrl+currPath, v.Body, currTag)
		}
	}
}

func analyseNewRouter(baseUrl string, ce *ast.CallExpr, stag string) {
	if ce == nil {
		return
	}
	if baseUrl == "" {
		baseUrl = "/"
	}
	_, err := url.ParseRequestURI(baseUrl)
	if err != nil {
		beeLogger.Log.Fatalf("analyseNewRouter:baseUrl<%s> is invalid", baseUrl)
		return
	}
	if len(ce.Args) < 2 {
		return
	}
	cname := "Service"

	selName := ce.Fun.(*ast.SelectorExpr).Sel.String()
	methods, ok := routerMethods(selName)
	if !ok {
		return
	}
	if _, ok := ce.Args[0].(*ast.BasicLit); !ok {
		// omit if router path is not static
		return
	}
	index := 0
	if selName == "Handle" {
		methods = []string{
			ce.Args[0].(*ast.BasicLit).Value,
		}
		index++
	}

	relativePath := strings.Trim(ce.Args[index].(*ast.BasicLit).Value, "\"")
	rt := baseUrl + relativePath
	handlers := ce.Args[index+1:]
	if len(handlers) == 0 {
		return
	}
	p := handlers[len(handlers)-1] // 只需要处理最后一个handler，前面的全部是middleware
	x := p.(*ast.SelectorExpr)
	//TODO 需要区分这里是直接引用第三方包的方法，还是使用的某个变量的方法
	//TODO 是否可以考虑去掉importlist?
	//TODO 目前所有的handler方法都写在了同一个包里面
	if v, ok := importlist[fmt.Sprint(x.X)]; ok {
		cname = v
	}
	if apis, ok := controllerList[cname]; ok {
		if item, ok := apis[x.Sel.Name]; ok {
			//key is funcName
			//not range over apis, seaching apis by funcName directly
			tag := cname
			if baseUrl != "" {
				tag = strings.Trim(baseUrl, "/")
			}
			if stag != "" {
				tag = stag
			}
			item = item.Copy()
			for _, method := range methods {
				switch method {
				case "GET":
					item.Get = item.Stash.Copy()
					item.Get.Tags = []string{tag}
				case "POST":
					item.Post = item.Stash.Copy()
					item.Post.Tags = []string{tag}
				case "DELETE":
					item.Delete = item.Stash.Copy()
					item.Delete.Tags = []string{tag}
				case "PATCH":
					item.Patch = item.Stash.Copy()
					item.Patch.Tags = []string{tag}
				case "PUT":
					item.Put = item.Stash.Copy()
					item.Put.Tags = []string{tag}
				case "OPTIONS":
					item.Options = item.Stash.Copy()
					item.Options.Tags = []string{tag}
				case "HEAD":
					item.Head = item.Stash.Copy()
					item.Head.Tags = []string{tag}
				}
			}
			if len(rootapi.Paths) == 0 {
				rootapi.Paths = make(map[string]*Item)
			}
			rt = urlReplace(rt)
			var err error
			item, err = item.Merge(rootapi.Paths[rt])
			if err != nil {
				beeLogger.Log.Fatalf("analyseNewRouter:%v\n", err)
			}
			rootapi.Paths[rt] = item
		}
	}

	return
}

// analyseNewNamespace returns version and the others params
func analyseNewNamespace(ce *ast.CallExpr) (first string, others []ast.Expr) {
	for i, p := range ce.Args {
		if i == 0 {
			switch pp := p.(type) {
			case *ast.BasicLit:
				first = strings.Trim(pp.Value, `"`)
			}
			continue
		}
		others = append(others, p)
	}
	return
}

func analyseNSInclude(baseurl string, ce *ast.CallExpr) string {
	cname := ""
	for _, p := range ce.Args {
		x := p.(*ast.UnaryExpr).X.(*ast.CompositeLit).Type.(*ast.SelectorExpr)
		if v, ok := importlist[fmt.Sprint(x.X)]; ok {
			cname = v + x.Sel.Name
		}
		if apis, ok := controllerList[cname]; ok {
			for rt, item := range apis {
				tag := cname
				if baseurl != "" {
					rt = baseurl + rt
					tag = strings.Trim(baseurl, "/")
				}
				if item.Get != nil {
					item.Get.Tags = []string{tag}
				}
				if item.Post != nil {
					item.Post.Tags = []string{tag}
				}
				if item.Put != nil {
					item.Put.Tags = []string{tag}
				}
				if item.Patch != nil {
					item.Patch.Tags = []string{tag}
				}
				if item.Head != nil {
					item.Head.Tags = []string{tag}
				}
				if item.Delete != nil {
					item.Delete.Tags = []string{tag}
				}
				if item.Options != nil {
					item.Options.Tags = []string{tag}
				}
				if len(rootapi.Paths) == 0 {
					rootapi.Paths = make(map[string]*Item)
				}
				rt = urlReplace(rt)
				rootapi.Paths[rt] = item
			}
		}
	}
	return cname
}

func analyseControllerPkg(vendorPath, localName, pkgpath string) {
	if pkgpath != "" {
		pkgpath = strings.Trim(pkgpath, "\"")
		if isSystemPackage(pkgpath) {
			return
		}
		if pkgpath == "github.com/astaxie/beego" ||
			strings.HasPrefix(pkgpath, "github.com/skOak/hee/") ||
			strings.HasPrefix(pkgpath, "github.com/") {
			return
		}
		if localName != "" {
			importlist[localName] = pkgpath
		} else {
			pps := strings.Split(pkgpath, "/")
			importlist[pps[len(pps)-1]] = pkgpath
		}
	}
	gopaths := bu.GetGOPATHs()
	if len(gopaths) == 0 {
		beeLogger.Log.Fatal("GOPATH environment variable is not set or empty")
	}
	pkgRealpath := ""

	wg, _ := filepath.EvalSymlinks(filepath.Join(vendorPath, pkgpath))
	if bu.FileExists(wg) {
		pkgRealpath = wg
	} else {
		wgopath := gopaths
		for _, wg := range wgopath {
			wg, _ = filepath.EvalSymlinks(filepath.Join(wg, "src", pkgpath))
			if bu.FileExists(wg) {
				pkgRealpath = wg
				break
			}
		}
	}
	if pkgRealpath != "" {
		if _, ok := pkgCache[pkgpath]; ok {
			return
		}
		pkgCache[pkgpath] = struct{}{}
	} else {
		beeLogger.Log.Fatalf("Package '%s' does not exist in the GOPATH or vendor path", pkgpath)
	}

	fileSet := token.NewFileSet()
	astPkgs, err := parser.ParseDir(fileSet, pkgRealpath, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	if err != nil {
		beeLogger.Log.Fatalf("Error while parsing dir at '%s': %s", pkgpath, err)
	}
	for _, pkg := range astPkgs {
		for _, fl := range pkg.Files {
			for _, d := range fl.Decls {
				switch specDecl := d.(type) {
				case *ast.FuncDecl:
					if specDecl.Recv != nil && len(specDecl.Recv.List) > 0 {
						if t, ok := specDecl.Recv.List[0].Type.(*ast.StarExpr); ok {
							// Parse controller method
							parserComments(specDecl, fmt.Sprint(t.X), pkgpath)
						}
					}
				case *ast.GenDecl:
					if specDecl.Tok == token.TYPE {
						for _, s := range specDecl.Specs {
							switch tp := s.(*ast.TypeSpec).Type.(type) {
							case *ast.StructType:
								_ = tp.Struct
								// Parse controller definition comments
								if strings.TrimSpace(specDecl.Doc.Text()) != "" {
									controllerComments[pkgpath+s.(*ast.TypeSpec).Name.String()] = specDecl.Doc.Text()
								}
							}
						}
					}
				}
			}
		}
	}
}

func isSystemPackage(pkgpath string) bool {
	goroot := os.Getenv("GOROOT")
	if goroot == "" {
		goroot = runtime.GOROOT()
	}
	if goroot == "" {
		beeLogger.Log.Fatalf("GOROOT environment variable is not set or empty")
	}

	wg, _ := filepath.EvalSymlinks(filepath.Join(goroot, "src", "pkg", pkgpath))
	if bu.FileExists(wg) {
		return true
	}

	//TODO(zh):support go1.4
	wg, _ = filepath.EvalSymlinks(filepath.Join(goroot, "src", pkgpath))
	return bu.FileExists(wg)
}

func peekNextSplitString(ss string) (s string, spacePos int) {
	spacePos = strings.IndexFunc(ss, unicode.IsSpace)
	if spacePos < 0 {
		s = ss
		spacePos = len(ss)
	} else {
		s = strings.TrimSpace(ss[:spacePos])
	}
	return
}

// parse the func comments
func parserComments(f *ast.FuncDecl, controllerName, pkgpath string) error {
	opts := Operation{
		Responses: make(map[string]Response),
	}
	funcName := f.Name.String()
	comments := f.Doc
	funcParamMap := buildParamMap(f.Type.Params)
	//TODO: resultMap := buildParamMap(f.Type.Results)
	if comments != nil && comments.List != nil {
		for _, c := range comments.List {
			t := strings.TrimSpace(strings.TrimLeft(c.Text, "//"))
			if strings.HasPrefix(t, "@Title") {
				opts.OperationID = controllerName + "." + strings.TrimSpace(t[len("@Title"):])
			} else if strings.HasPrefix(t, "@Description") {
				opts.Description = strings.TrimSpace(t[len("@Description"):])
			} else if strings.HasPrefix(t, "@Summary") {
				opts.Summary = strings.TrimSpace(t[len("@Summary"):])
			} else if strings.HasPrefix(t, "@Success") {
				ss := strings.TrimSpace(t[len("@Success"):])
				rs := Response{}
				respCodeMsg, pos := peekNextSplitString(ss)
				ss = strings.TrimSpace(ss[pos:])
				respType, pos := peekNextSplitString(ss)
				if respType == "{object}" || respType == "{array}" {
					isArray := respType == "{array}"
					ss = strings.TrimSpace(ss[pos:])
					schemaName, _ := peekNextSplitString(ss)
					if schemaName == "" {
						beeLogger.Log.Fatalf("[%s.%s] Schema must follow {object} or {array}", controllerName, funcName)
					}
					if strings.HasPrefix(schemaName, "[]") {
						schemaName = schemaName[2:]
						isArray = true
					}
					schema := Schema{}
					if sType, ok := basicTypes[schemaName]; ok {
						typeFormat := strings.Split(sType, ":")
						schema.Type = typeFormat[0]
						schema.Format = typeFormat[1]
					} else {
						m, mod, realTypes := getModel(pkgpath, controllerName, schemaName)
						schema.Ref = "#/definitions/" + m
						if _, ok := modelsList[pkgpath+controllerName]; !ok {
							modelsList[pkgpath+controllerName] = make(map[string]Schema)
						}
						modelsList[pkgpath+controllerName][schemaName] = mod
						appendModels(pkgpath, controllerName, realTypes, funcName)
					}
					if isArray {
						rs.Schema = &Schema{
							Type:  "array",
							Items: &schema,
						}
					} else {
						rs.Schema = &schema
					}
				}
				respCode, respMsg := getRespCodeMsg(pkgpath, controllerName, funcName, respCodeMsg)
				rs.Description = respMsg
				opts.Responses[respCode] = rs
			} else if strings.HasPrefix(t, "@Param") {
				para := Parameter{}
				p := getparams(strings.TrimSpace(t[len("@Param "):]))
				if len(p) < 4 {
					beeLogger.Log.Fatal(controllerName + "_" + funcName + "'s comments @Param should have at least 4 params")
				}
				paramNames := strings.SplitN(p[0], "=>", 2)
				para.Name = paramNames[0]
				funcParamName := para.Name
				if len(paramNames) > 1 {
					funcParamName = paramNames[1]
				}
				paramType, ok := funcParamMap[funcParamName]
				if ok {
					delete(funcParamMap, funcParamName)
				}

				switch p[1] {
				case "query":
					fallthrough
				case "header":
					fallthrough
				case "path":
					fallthrough
				case "formData":
					fallthrough
				case "body":
					break
				default:
					beeLogger.Log.Fatalf("[%s.%s] Unknown param location: %s. Possible values are `query`, `header`, `path`, `formData` or `body`.\n", controllerName, funcName, p[1])
				}
				para.In = p[1]
				pp := strings.Split(p[2], ".")
				typ := pp[len(pp)-1]
				if len(pp) >= 2 {
					m, mod, realTypes := getModel(pkgpath, controllerName, p[2])
					para.Schema = &Schema{
						Ref: "#/definitions/" + m,
					}
					if _, ok := modelsList[pkgpath+controllerName]; !ok {
						modelsList[pkgpath+controllerName] = make(map[string]Schema)
					}
					modelsList[pkgpath+controllerName][typ] = mod
					appendModels(pkgpath, controllerName, realTypes, f.Name.Name)
				} else {
					if typ == "auto" {
						typ = paramType
					}
					setParamType(&para, typ, pkgpath, controllerName)
				}
				switch len(p) {
				case 5:
					para.Required, _ = strconv.ParseBool(p[3])
					para.Description = strings.Trim(p[4], `" `)
				case 6:
					para.Default = str2RealType(p[3], para.Type)
					para.Required, _ = strconv.ParseBool(p[4])
					para.Description = strings.Trim(p[5], `" `)
				default:
					para.Description = strings.Trim(p[3], `" `)
				}
				opts.Parameters = append(opts.Parameters, para)
			} else if strings.HasPrefix(t, "@Failure") {
				ss := strings.TrimSpace(t[len("@Failure"):])
				rs := Response{}
				respCodeMsg, pos := peekNextSplitString(ss)
				ss = strings.TrimSpace(ss[pos:])
				respType, pos := peekNextSplitString(ss)
				if respType == "{object}" || respType == "{array}" {
					isArray := respType == "{array}"
					ss = strings.TrimSpace(ss[pos:])
					schemaName, _ := peekNextSplitString(ss)
					if schemaName == "" {
						beeLogger.Log.Fatalf("[%s.%s] Schema must follow {object} or {array}", controllerName, funcName)
					}
					if strings.HasPrefix(schemaName, "[]") {
						schemaName = schemaName[2:]
						isArray = true
					}
					schema := Schema{}
					if sType, ok := basicTypes[schemaName]; ok {
						typeFormat := strings.Split(sType, ":")
						schema.Type = typeFormat[0]
						schema.Format = typeFormat[1]
					} else {
						m, mod, realTypes := getModel(pkgpath, controllerName, schemaName)
						schema.Ref = "#/definitions/" + m
						if _, ok := modelsList[pkgpath+controllerName]; !ok {
							modelsList[pkgpath+controllerName] = make(map[string]Schema)
						}
						modelsList[pkgpath+controllerName][schemaName] = mod
						appendModels(pkgpath, controllerName, realTypes, f.Name.Name)
					}
					if isArray {
						rs.Schema = &Schema{
							Type:  "array",
							Items: &schema,
						}
					} else {
						rs.Schema = &schema
					}
				}
				respCode, respMsg := getRespCodeMsg(pkgpath, controllerName, funcName, respCodeMsg)
				rs.Description = respMsg
				opts.Responses[respCode] = rs
			} else if strings.HasPrefix(t, "@Deprecated") {
				opts.Deprecated, _ = strconv.ParseBool(strings.TrimSpace(t[len("@Deprecated"):]))
			} else if strings.HasPrefix(t, "@Accept") {
				accepts := strings.Split(strings.TrimSpace(strings.TrimSpace(t[len("@Accept"):])), ",")
				for _, a := range accepts {
					switch a {
					case "json":
						opts.Consumes = append(opts.Consumes, ajson)
						opts.Produces = append(opts.Produces, ajson)
					case "xml":
						opts.Consumes = append(opts.Consumes, axml)
						opts.Produces = append(opts.Produces, axml)
					case "plain":
						opts.Consumes = append(opts.Consumes, aplain)
						opts.Produces = append(opts.Produces, aplain)
					case "html":
						opts.Consumes = append(opts.Consumes, ahtml)
						opts.Produces = append(opts.Produces, ahtml)
					case "form":
						opts.Consumes = append(opts.Consumes, aform)
					}
				}
			} else if strings.HasPrefix(t, "@Security") {
				if len(opts.Security) == 0 {
					opts.Security = make([]map[string][]string, 0)
				}
				opts.Security = append(opts.Security, getSecurity(t))
			} else if strings.HasPrefix(t, "@Author") {
				opts.Author = strings.Split(strings.TrimSpace(strings.TrimSpace(t[len("@Author"):])), ",")
			}
		}

		if len(opts.Author) > 0 {
			for i := range opts.Author {
				opts.Author[i] = "@" + opts.Author[i]
			}
			opts.Description = fmt.Sprintf("[%v]%v", strings.Join(opts.Author, " "), opts.Description)
		}
	}

	var item *Item
	if itemList, ok := controllerList[pkgpath+controllerName]; ok {
		if it, ok := itemList[funcName]; !ok {
			item = &Item{}
		} else {
			item = it
		}
	} else {
		controllerList[pkgpath+controllerName] = make(map[string]*Item)
		item = &Item{}
	}
	item.Stash = &opts
	controllerList[pkgpath+controllerName][funcName] = item
	return nil
}

func setParamType(para *Parameter, typ string, pkgpath, controllerName string) {
	isArray := false
	paraType := ""
	paraFormat := ""

	if strings.HasPrefix(typ, "[]") {
		typ = typ[2:]
		isArray = true
	}
	if typ == "string" || typ == "number" || typ == "integer" || typ == "boolean" ||
		typ == "array" || typ == "file" {
		paraType = typ
	} else if sType, ok := basicTypes[typ]; ok {
		typeFormat := strings.Split(sType, ":")
		paraType = typeFormat[0]
		paraFormat = typeFormat[1]
	} else {
		m, mod, realTypes := getModel(pkgpath, controllerName, typ)
		para.Schema = &Schema{
			Ref: "#/definitions/" + m,
		}
		if _, ok := modelsList[pkgpath+controllerName]; !ok {
			modelsList[pkgpath+controllerName] = make(map[string]Schema)
		}
		modelsList[pkgpath+controllerName][typ] = mod
		appendModels(pkgpath, controllerName, realTypes, para.Name)
	}
	if isArray {
		para.Type = "array"
		para.Items = &ParameterItems{
			Type:   paraType,
			Format: paraFormat,
		}
	} else {
		para.Type = paraType
		para.Format = paraFormat
	}

}

func paramInPath(name, route string) bool {
	return strings.HasSuffix(route, ":"+name) ||
		strings.Contains(route, ":"+name+"/")
}

func getFunctionParamType(t ast.Expr) string {
	switch paramType := t.(type) {
	case *ast.Ident:
		return paramType.Name
	// case *ast.Ellipsis:
	// 	result := getFunctionParamType(paramType.Elt)
	// 	result.array = true
	// 	return result
	case *ast.ArrayType:
		return "[]" + getFunctionParamType(paramType.Elt)
	case *ast.StarExpr:
		return getFunctionParamType(paramType.X)
	case *ast.SelectorExpr:
		return getFunctionParamType(paramType.X) + "." + paramType.Sel.Name
	default:
		return ""

	}
}

func buildParamMap(list *ast.FieldList) map[string]string {
	i := 0
	result := map[string]string{}
	if list != nil {
		funcParams := list.List
		for _, fparam := range funcParams {
			param := getFunctionParamType(fparam.Type)
			var paramName string
			if len(fparam.Names) > 0 {
				paramName = fparam.Names[0].Name
			} else {
				paramName = fmt.Sprint(i)
				i++
			}
			result[paramName] = param
		}
	}
	return result
}

// analisys params return []string
// @Param	query		form	 string	true		"The email for login"
// [query form string true "The email for login"]
func getparams(str string) []string {
	var s []rune
	var j int
	var start bool
	var r []string
	var quoted int8
	for _, c := range str {
		if unicode.IsSpace(c) && quoted == 0 {
			if !start {
				continue
			} else {
				start = false
				j++
				r = append(r, string(s))
				s = make([]rune, 0)
				continue
			}
		}

		start = true
		if c == '"' {
			quoted ^= 1
			continue
		}
		s = append(s, c)
	}
	if len(s) > 0 {
		r = append(r, string(s))
	}
	return r
}

func getRespCodeMsg(pkgpath, controllerName, funcName, str string) (string, string) {
	code := ""
	msg := ""
	strs := strings.Split(str, ".")
	objectname := strs[len(strs)-1]
	for _, pkg := range astPkgs {
		if strs[0] == pkg.Name {
			for _, fl := range pkg.Files {
				for k, d := range fl.Scope.Objects {
					if d.Kind == ast.Var {
						if k != objectname {
							continue
						}
						as, ok := d.Decl.(*ast.ValueSpec)
						if !ok {
							beeLogger.Log.Fatalf("Unknown var definition without ValueSpec %+#v\n", d.Decl)
						}
						args := as.Values[0].(*ast.CallExpr).Args
						if len(args) < 2 {
							beeLogger.Log.Fatalf("Invalid arguments in CallExpr: %+#v\n", as.Values)
						}
						code = args[0].(*ast.BasicLit).Value
						msg = args[1].(*ast.BasicLit).Value
						goto done
					}
				}
			}
		}
	}
done:
	if code == "" {
		beeLogger.Log.Warnf("Cannot find the response code&msg: [%v@%v_%v]%s", funcName, pkgpath, controllerName, str)
		// TODO remove when all type have been supported
		//os.Exit(1)
	}
	//return "200", fmt.Sprintf(`{"code":%s,"msg":"%s"}`, code, msg)
	return code, msg
}

func getModel(pkgpath, controllerName, str string) (objectname string, m Schema, realTypes []string) {
	strs := strings.Split(str, ".")
	objectname = strs[len(strs)-1]
	packageName := ""
	m.Type = "object"
	for _, pkg := range astPkgs {
		if strs[0] == pkg.Name {
			for _, fl := range pkg.Files {
				for k, d := range fl.Scope.Objects {
					if d.Kind == ast.Typ {
						if k != objectname {
							continue
						}
						packageName = pkg.Name
						parseObject(d, k, &m, &realTypes, astPkgs, pkg.Name, fl)
						goto done
					}
				}
			}
		}
	}
done:
	if m.Title == "" {
		beeLogger.Log.Fatalf("Cannot find the object: [%v@%v]%s", controllerName, pkgpath, str)
	}
	if len(rootapi.Definitions) == 0 {
		rootapi.Definitions = make(map[string]Schema)
	}
	objectname = packageName + "." + objectname
	rootapi.Definitions[objectname] = m
	return
}

func parseObject(d *ast.Object, k string, m *Schema, realTypes *[]string, astPkgs []*ast.Package, packageName string, f *ast.File) {
	ts, ok := d.Decl.(*ast.TypeSpec)
	if !ok {
		beeLogger.Log.Fatalf("Unknown type without TypeSec: %v\n", d)
	}
	// TODO support other types, such as `ArrayType`, `MapType`, `InterfaceType` etc...
	st, ok := ts.Type.(*ast.StructType)
	if !ok {
		goto enum
	}
	m.Title = k
	if st.Fields.List != nil {
		m.Properties = make(map[string]Propertie)
		for _, field := range st.Fields.List {
			isSlice, realType, sType := typeAnalyser(field)
			if (isSlice && isBasicType(realType)) || sType == "object" {
				if len(strings.Split(realType, " ")) > 1 {
					realType = strings.Replace(realType, " ", ".", -1)
					realType = strings.Replace(realType, "&", "", -1)
					realType = strings.Replace(realType, "{", "", -1)
					realType = strings.Replace(realType, "}", "", -1)
				} else {
					realType = packageName + "." + realType
				}
			}
			*realTypes = append(*realTypes, realType)
			mp := Propertie{}
			if isSlice {
				mp.Type = "array"
				if isBasicType(strings.Replace(realType, "[]", "", -1)) {
					typeFormat := strings.Split(sType, ":")
					mp.Items = &Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				} else {
					mp.Items = &Propertie{
						Ref: "#/definitions/" + realType,
					}
				}
			} else {
				if sType == "object" {
					mp.Ref = "#/definitions/" + realType
				} else if isBasicType(realType) {
					typeFormat := strings.Split(sType, ":")
					mp.Type = typeFormat[0]
					mp.Format = typeFormat[1]
				} else if realType == "map" {
					typeFormat := strings.Split(sType, ":")
					mp.AdditionalProperties = &Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				}
			}
			if field.Comment != nil {
				mp.Description = field.Comment.Text()
			}
			if field.Names != nil {
				// set property name as field name
				var name = field.Names[0].Name

				// if no tag skip tag processing
				if field.Tag == nil {
					m.Properties[name] = mp
					continue
				}

				var tagValues []string

				stag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))

				defaultValue := stag.Get("doc")
				if defaultValue != "" {
					r, _ := regexp.Compile(`default\((.*)\)`)
					if r.MatchString(defaultValue) {
						res := r.FindStringSubmatch(defaultValue)
						mp.Default = str2RealType(res[1], realType)

					} else {
						beeLogger.Log.Warnf("Invalid default value: %s", defaultValue)
					}
				}

				tag := stag.Get("json")

				if tag != "" {
					tagValues = strings.Split(tag, ",")
				}

				// dont add property if json tag first value is "-"
				if len(tagValues) == 0 || tagValues[0] != "-" {

					// set property name to the left most json tag value only if is not omitempty
					if len(tagValues) > 0 && tagValues[0] != "omitempty" {
						name = tagValues[0]
					}

					if thrifttag := stag.Get("thrift"); thrifttag != "" {
						ts := strings.Split(thrifttag, ",")
						if ts[0] != "" {
							name = ts[0]
						}
					}
					if required := stag.Get("required"); required != "" {
						m.Required = append(m.Required, name)
					}
					if desc := stag.Get("description"); desc != "" {
						mp.Description = desc
					}
					if example := stag.Get("example"); example != "" {
						mp.Example = example
					}

					m.Properties[name] = mp
				}
				if ignore := stag.Get("ignore"); ignore != "" {
					continue
				}
			} else {
				// 当前只处理嵌入类型为struct类型的情况,*struct和interface暂时没有处理(这两种case对于swagger文档导出应该没有任何用处)
				tag := ""
				if field.Tag != nil {
					stag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
					tag = stag.Get("json")
				}

				if tag != "" {
					tagValues := strings.Split(tag, ",")
					if tagValues[0] == "-" {
						//if json tag is "-", omit
						continue
					} else {
						//if json tag is "something", output: something #definition/pkgname.Type
						m.Properties[tagValues[0]] = mp
						continue
					}
				} else {
					//if no json tag, embed all the fields of the type here
					nm := &Schema{}
					for _, pkg := range astPkgs {
						for _, fl := range pkg.Files {
							for nameOfObj, obj := range fl.Scope.Objects {
								if obj.Name == fmt.Sprint(field.Type) {
									parseObject(obj, nameOfObj, nm, realTypes, astPkgs, pkg.Name, fl)
								}
							}
						}
					}
					for name, p := range nm.Properties {
						m.Properties[name] = p
					}
					continue
				}
			}
		}
	}
	return

enum:
	// Support enum type
	bt, ok := ts.Type.(*ast.Ident)
	if !ok {
		return
	}
	sType, ok := basicTypes[bt.Name]
	if !ok {
		return
	}
	typeFormat := strings.Split(sType, ":")
	m.Type = typeFormat[0]
	m.Title = k
	m.Description = ts.Comment.Text()
	ds := make([]string, 0)
	dm := make(map[string]string)
	for _, d := range f.Scope.Objects {
		if d.Kind == ast.Con || d.Kind == ast.Var {
			vs, ok := d.Decl.(*ast.ValueSpec)
			if !ok {
				continue
			}
			vst, ok := vs.Type.(*ast.Ident)
			if !ok {
				continue
			}
			if k != vst.Name {
				continue
			}
			for i := 0; i < len(vs.Values); i++ {
				vsv, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					continue
				}
				ds = append(ds, vsv.Value)
				dm[vsv.Value] = fmt.Sprintf("  * `%v` - %s", vsv.Value, vs.Comment.Text())
			}
		}
	}
	if len(ds) > 0 {
		sort.Slice(ds, func(i, j int) bool {
			di, erri := strconv.ParseInt(ds[i], 10, 64)
			dj, errj := strconv.ParseInt(ds[j], 10, 64)
			if erri == nil && errj == nil {
				return di < dj
			}
			return ds[i] < ds[j]
		})
		for _, s := range ds {
			m.Description += dm[s]
		}
	}
	return
}

func typeAnalyser(f *ast.Field) (isSlice bool, realType, swaggerType string) {
	if arr, ok := f.Type.(*ast.ArrayType); ok {
		if isBasicType(fmt.Sprint(arr.Elt)) {
			return true, fmt.Sprintf("[]%v", arr.Elt), basicTypes[fmt.Sprint(arr.Elt)]
		}
		if mp, ok := arr.Elt.(*ast.MapType); ok {
			return false, fmt.Sprintf("map[%v][%v]", mp.Key, mp.Value), "object"
		}
		if star, ok := arr.Elt.(*ast.StarExpr); ok {
			return true, fmt.Sprint(star.X), "object"
		}
		return true, fmt.Sprint(arr.Elt), "object"
	}
	switch t := f.Type.(type) {
	case *ast.StarExpr:
		basicType := fmt.Sprint(t.X)
		if k, ok := basicTypes[basicType]; ok {
			return false, basicType, k
		}
		return false, basicType, "object"
	case *ast.MapType:
		val := fmt.Sprintf("%v", t.Value)
		if isBasicType(val) {
			return false, "map", basicTypes[val]
		}
		if _, ok := t.Value.(*ast.InterfaceType); ok {
			return false, "map", basicTypes["interface{}"]
		}
		return false, val, "object"
	case *ast.Ident: // embed struct [pkgName.]TypeName
		basicType := fmt.Sprint(t)
		if k, ok := basicTypes[basicType]; ok {
			return false, basicType, k
		}
		return false, basicType, "object"
	}
	basicType := fmt.Sprint(f.Type)
	if object, isStdLibObject := stdlibObject[basicType]; isStdLibObject {
		basicType = object
	}
	if k, ok := basicTypes[basicType]; ok {
		return false, basicType, k
	}
	return false, basicType, "object"
}

func isBasicType(Type string) bool {
	if _, ok := basicTypes[Type]; ok {
		return true
	}
	return false
}

// append models
func appendModels(pkgpath, controllerName string, realTypes []string, extra ...string) {
	for _, realType := range realTypes {
		if realType != "" && !isBasicType(strings.TrimLeft(realType, "[]")) &&
			!strings.HasPrefix(realType, "map") && !strings.HasPrefix(realType, "&") {
			if _, ok := modelsList[pkgpath+controllerName][realType]; ok {
				continue
			}
			if len(extra) > 0 {
				_, mod, newRealTypes := getModel(pkgpath, extra[0], realType)
				modelsList[pkgpath+controllerName][realType] = mod
				appendModels(pkgpath, controllerName, newRealTypes, extra...)
			} else {
				_, mod, newRealTypes := getModel(pkgpath, controllerName, realType)
				modelsList[pkgpath+controllerName][realType] = mod
				appendModels(pkgpath, controllerName, newRealTypes)
			}
		}
	}
}

func getSecurity(t string) (security map[string][]string) {
	security = make(map[string][]string)
	p := getparams(strings.TrimSpace(t[len("@Security"):]))
	if len(p) == 0 {
		beeLogger.Log.Fatalf("No params for security specified\n")
	}
	security[p[0]] = make([]string, 0)
	for i := 1; i < len(p); i++ {
		security[p[0]] = append(security[p[0]], p[i])
	}
	return
}

func urlReplace(src string) string {
	src = strings.Replace(src, "//", "/", -1)
	pt := strings.Split(src, "/")
	for i, p := range pt {
		if len(p) > 0 {
			if p[0] == ':' {
				pt[i] = "{" + p[1:] + "}"
			} else if p[0] == '?' && p[1] == ':' {
				pt[i] = "{" + p[2:] + "}"
			}
		}
	}
	return strings.Join(pt, "/")
}

func str2RealType(s string, typ string) interface{} {
	var err error
	var ret interface{}

	switch typ {
	case "int", "int64", "int32", "int16", "int8":
		ret, err = strconv.Atoi(s)
	case "bool":
		ret, err = strconv.ParseBool(s)
	case "float64":
		ret, err = strconv.ParseFloat(s, 64)
	case "float32":
		ret, err = strconv.ParseFloat(s, 32)
	default:
		return s
	}

	if err != nil {
		beeLogger.Log.Warnf("Invalid default value type '%s': %s", typ, s)
		return s
	}

	return ret
}
