#!lua

--[[
This script is meant to be run form the root repo folder:

$ ./scripts/lua/build.lua 

--]]

require "pl" -- penlight

local F = require "F" -- f-strings
local lfs = require "lfs" -- Lua File System
local toml = require "toml" -- lua-toml

local options = app.parse_args()
local rootConfiguration = toml.parse(file.read("content/configuration.toml"))

local markdownFiles = {}
local configurations = {}

--[[
The documentation is divided into discreet folders that should be viewed as
complete "books" or "namespaces".

Each of these folders have their own configuration file that sets which files
should be included in the documentation, the title for the part, and what is the
table of contents depth.

There is a lot of juggling in this script to handle the table of contents. 

---------------------------------------------------------------------------------

Git submodules are used to include SSB specifications and content from other git
repositories into this documentation repo.

In these cases, we can't force the original repository to contain a "configuration.toml"
file and must traverse their folders to find out all markdown files.

To detect which folders are submodules, we look for a ".git" folder inside them.
--]]
for index, fileOrFolder in pairs(rootConfiguration.files) do
	if path.isfile(F"content/{fileOrFolder}") then
		table.insert(markdownFiles, F"content/{fileOrFolder}")
	elseif path.isdir(F"content/{fileOrFolder}") then 
		if path.exists(F"content/{fileOrFolder}/configuration.toml") then
			local configuration = toml.parse(file.read(F"content/{fileOrFolder}/configuration.toml"))

			for i, mfile in ipairs(configuration.files) do

				if path.isfile(F"content/{fileOrFolder}/{mfile}") then
					table.insert(markdownFiles, F"content/{fileOrFolder}/{mfile}")
					configurations[fileOrFolder] = configuration
				end

				if path.isfile(F"content/{fileOrFolder}/{mfile}/.git") then
					-- git submodule found, find all Markdown files in it.
					local submoduleMarkdownFiles = dir.getallfiles(F"content/{fileOrFolder}/{mfile}", "*.md")

					
					local readme
					function filterReadmes(v, a)

						if stringx.endswith(string.lower(v), a) then
							readme = v 
							return false
						end

						--[[ 
						QUIRK: remove presentation files.

						The metafeeds repo has a markdown file that is used to generate a presentation and
						is not compatible with this repo. It needs to be ignored.
						]]--

						if stringx.endswith(string.lower(v), "presentation.md") then
							return false
						end

						return true
					end

					submoduleMarkdownFiles = tablex.filter(submoduleMarkdownFiles, filterReadmes, F"content/{fileOrFolder}/{mfile}/readme.md")
					
					table.insert(markdownFiles, readme)
					tablex.insertvalues(markdownFiles, submoduleMarkdownFiles)
					configurations[F"{fileOrFolder}/{mfile}"] = {
						toc_depth = 2,
						submodule = true,
						files = submoduleMarkdownFiles
					}
				end
			end
		end

	end
end

print "Assembling HTML..."

local toc = {}

for index, f in pairs(markdownFiles) do
	local source = f

	local destination = f:gsub(".md", ".html")
	destination = destination:gsub("content/", "docs/")
	destination = destination:gsub("README.html", "index.html")
	destination = destination:gsub("readme.html", "index.html")
	
	local destinationPath = path.dirname(destination)
	local folder = destinationPath:gsub("docs/","")
	local toc_depth = 1 

	if folder ~= "docs" and configurations[folder] ~= nil then 
		toc_depth = configurations[folder].toc_depth
	else
		toc_depth = 1
	end
		
	if destinationPath ~= "" and not path.exists(destinationPath) then
		local ok, err, exitCode = os.execute(F"mkdir -p {destinationPath}")
		
		if not ok then
			print(F"Error: {err}")
			print(F"path: {destinationPath}")
			os.exit(exitCode)
		end
	end
	
		
	local cmd = F"pandoc  --lua-filter ./scripts/lua/execute_inline_lua.lua --lua-filter ./scripts/lua/fix_links.lua -F mermaid-filter --lua-filter ./scripts/lua/fix_svg.lua --template=./templates/simple/simple.html --css=simple.css -V current_date=\"$(date +%Y-%m-%d%n)\" --from markdown --toc --standalone --toc-depth={toc_depth} --to html5 --output {destination} {source}"
	
	if options.verbose then
		print(cmd)
	end
	
	local ok, err, exitCode = os.execute(cmd)
	
	if not ok then
		print(F"Error: {err}")
		os.exit(exitCode)
	end
	
	-- Add filename back into toc item.
	local content = file.read(F"{destination}")
	local link = destination:gsub("docs/", "")
	content = content:gsub('href="#', F'class="toc-item" href="/{link}#')
	local ok, err = file.write(F"{destination}", content)
	
	-- extract partial table of contents from file
	local s = 0
	local e = 0
	local lines = stringx.splitlines(content)
	for index, line in pairs(lines) do 
		if stringx.lfind(line, "<nav") then
			s = index
		end
		
		if stringx.lfind(line, "</nav") then
			e = index
		end
	end
			
	local t =  table.move(lines, s+2, e-2, 1, {})
	
	-- adding header from configuration.toml
	for folder,conf in pairs(configurations) do
		if stringx.startswith(link, folder) then
			local b = path.basename(link):gsub(".html",".md"):gsub("index","README"):gsub("index","readme")
			local d = path.dirname(link)
			if b == conf.files[1] and path.exists(F"content/{d}/configuration.toml") then
				table.insert(t, 1, F"<h1 class=\"toc-title\">{conf.title}</h1>")
			end
		end
	end

	-- if it is an empty t, add a link to itself
	if #t == 0 then
		local b = path.basename(link)
		t = {F"<ul><li><a class=\"toc-item\" href=\"/{link}\">{b}</a></li></ul>"}
	end

	-- if it is a submodule, only use README.md as part of the ToC.
	local submodule = false

	local function tsort(x,y) 
		return #x > #y 
	end
	
	for f,v in tablex.sort(configurations, tsort) do
		if stringx.startswith(folder, f) and configurations[f].submodule ~= nil then
			submodule = configurations[f].submodule
		end
	end
	
	if submodule and options.verbose then
		print(F"!!! {folder} is a submodule.")
	end

	if not submodule then
		tablex.insertvalues(toc, t)
	end

	if submodule and configurations[path.dirname(link)] ~= nil and path.basename(link) == "index.html" then
		tablex.insertvalues(toc, t)
	end
	
	print(F"Pandoc: {destination}")
end

if options.verbose then
	pretty.dump(markdownFiles)
end

for index, f in pairs(markdownFiles) do
	-- extract ToC from file
	local source = f
	local destination = f:gsub(".md", ".html"):gsub("content/", "docs/")
	destination = destination:gsub("README.html", "index.html")
	destination = destination:gsub("readme.html", "index.html")

	local content = file.read(F"{destination}")
	local s = 0
	local e = 0
	local lines = stringx.splitlines(content)
	
	for index, line in pairs(lines) do 
		if stringx.lfind(line, "<nav") then
			s = index
		end
		
		if stringx.lfind(line, "</nav") then
			e = index
		end
	end

	local newContent

	if s ~= 0 and e ~= 0 then
		-- Assemble new content for current file
		-- by replacing the ToC with the master ToC
		newContent = table.move(lines, 1, s+1, 1, {})
		
		-- newContent = table.move(toc, 1, #toc, #newContent, newContent)
		
		-- newContent = table.move(lines, e-1, #lines, #newContent, newContent)

		tablex.insertvalues(newContent, toc)

		tablex.move(newContent, lines, #newContent+1, e)
		
		if #newContent ~= 0 then
			newContent = stringx.join("\n", newContent)
		end
	else
		--[[ 
		file without ToC elements, just insert the ToC.

		The problem is that since it does not have a ToC, we can't find the position to insert it.

		So there are some hardcoded values computed from the template.
		]]--

		for ii, ll in pairs(lines) do 
			if stringx.lfind(ll, "<article") then
				s = ii - 1
				e = ii
			end
		end

		newContent = table.move(lines, 1, s, 1, {})
		tablex.insertvalues(newContent, {
			"<aside>",
			"<div class=\"logo\">",
			"  <img src=\"/icon96.png\">",
			"</div>",
			"<nav id=\"TOC\" role=\"doc-toc\">",
			"<ul>"
		})
		tablex.insertvalues(newContent, toc)
		tablex.insertvalues(newContent, {
			"</ul>",
			"</nav>",
			"<div class=\"aside-footer\">",
			"<p>Build date:".. os.date() .. "</p>",
			"</div>",
			"</aside>"
		})
		tablex.move(newContent, lines, #newContent+1, e)

		newContent = stringx.join("\n",newContent) --'<nav id="TOC" role="doc-toc">' .. stringx.join("\n", toc) .. '</nav>'
	end
	
	local ok, err = file.write(F"{destination}", newContent)
	
	if not ok then
		print(F"Error: {err}")
		os.exit(exitCode)
	end
	
	if options.verbose then
		print(F"Refactored ToC: {destination}")
	end
	
end

local otherFiles = dir.getallfiles("./content")
local themeFiles = dir.getallfiles("./templates/simple")

tablex.insertvalues(otherFiles, themeFiles)


for index, f in pairs(otherFiles) do
	local extentionsToCopy = { ".html", ".css", ".svg", ".jpg", ".png" }
	if tablex.find(extentionsToCopy, path.extension(f)) ~= nil then
		local destination = f:gsub("./content", "./docs"):gsub("./templates/simple", "./docs")
		local destinationPath = path.dirname(destination)
		
		if not path.exists(destinationPath) then
			local ok, err, exitCode = os.execute(F"mkdir -p {destinationPath}")
			
			if not ok then
				print(F"Error: {err}")
				os.exit(exitCode)
			end
		end
		
		local ok, err, exitCode = file.copy(f, destination)

		if not ok then
			print(F"Error: {err}")
			os.exit(exitCode)
		end
		
		if options.verbose then
			print(F"Copy file: {f} --> {destination}")
		end
	end
end

print "HTML: OK"	

os.exit(0)
