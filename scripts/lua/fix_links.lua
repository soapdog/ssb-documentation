--[[ 
This is a Pandoc filter to fix internal links in both the PDF and the HTML.

To make this work, the link need to be pointing at a file and there must be an anchor
at the top of the target file that matches the normalised name of the file sans the extension

Ie: a file called "overview.md" there should be a "{#overview}" at the first H1 header in that
file.
--]]
function string:endswith(ending)
    return ending == "" or self:sub(-#ending) == ending
end

function Link(el)
  local old = el.target

  if FORMAT:match "latex" then
    if el.target:endswith ".md" then
      -- local link
      local newLink = el.target:gsub(".md","")
      el.target = ("#" .. newLink)
    end
  end

  if FORMAT:match "html5" then
    if el.target:endswith ".md"  then
      -- local link
      el.target = el.target:gsub("README.md","index.html")
      el.target = el.target:gsub(".md",".html")
    end
  end

  -- print(old .. " ---> " .. el.target)

  return el
end