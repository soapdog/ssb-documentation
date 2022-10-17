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
--]]
for index, fileOrFolder in pairs(rootConfiguration.files) do
	if path.isdir(F"content/{fileOrFolder}") then 
		if path.exists(F"content/{fileOrFolder}/configuration.toml") then
			local configuration = toml.parse(file.read(F"content/{fileOrFolder}/configuration.toml"))
			local files = tablex.imap(function(v) return "content/" .. fileOrFolder .. "/"  .. v end, configuration.files)

			tablex.insertvalues(markdownFiles, files)

			configurations[fileOrFolder] = configuration
		end
	end

	if path.isfile(F"content/{fileOrFolder}") then
		table.insert(markdownFiles, F"content/{fileOrFolder}")
	end
end

print "Assembling HTML..."

local toc = {}

for index, f in pairs(markdownFiles) do
	local source = f

	local destination = f:gsub(".md", ".html")
	destination = destination:gsub("content/", "docs/")
	destination = destination:gsub("README.html", "index.html")
	
	local destinationPath = path.dirname(destination)
	local folder = destinationPath:gsub("docs/","")
	local toc_depth = 1 

	if folder ~= "docs" then 
		toc_depth = configurations[folder].toc_depth
	end
		
	if destinationPath ~= "" and not path.exists(destinationPath) then
		local ok, err, exitCode = os.execute(F"mkdir -p {destinationPath}")
		
		if not ok then
			print(F"Error: {err}")
			print(F"path: {destinationPath}")
			os.exit(exitCode)
		end
	end
	
		
	local cmd = F"pandoc  --lua-filter ./scripts/lua/fix_links.lua -F mermaid-filter --lua-filter ./scripts/lua/fix_svg.lua --template=./templates/simple/simple.html --css=simple.css -V current_date=\"$(date +%Y-%m-%d%n)\" --from markdown --toc --standalone --toc-depth={toc_depth} --to html5 --output {destination} {source}"
	
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
	
	for folder,conf in pairs(configurations) do
		if stringx.startswith(link, folder) then
			local b = path.basename(link):gsub(".html",".md"):gsub("index","README")
			if b == conf.files[1] then
				table.insert(t, 1, F"<h1 class=\"toc-title\">{conf.title}</h1>")
			end
		end
	end

	tablex.insertvalues(toc,t)
	
	print(F"Pandoc: {destination}")
end

for index, f in pairs(markdownFiles) do
	-- extract ToC from file
	local source = f
	local destination = f:gsub(".md", ".html"):gsub("content/", "docs/")
	destination = destination:gsub("README.html", "index.html")

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
	
	-- Assemble new content for current file
	-- by replacing the ToC with the master ToC
	local newContent = table.move(lines, 1, s+1, 1, {})
	
	-- newContent = table.move(toc, 1, #toc, #newContent, newContent)
	
	-- newContent = table.move(lines, e-1, #lines, #newContent, newContent)

	tablex.insertvalues(newContent, toc)

	tablex.move(newContent, lines, #newContent+1, e)
	
	newContent = stringx.join("\n", newContent)
	
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
	local skipExtensions = { ".md", ".toml", ".DS_Store", ".html" }
	if tablex.find(skipExtensions, path.extension(f)) == nil then
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
