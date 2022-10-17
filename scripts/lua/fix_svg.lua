--[[ 
This is a Pandoc filter to fix path references for runtime generated images.

At the moment it is needed for the mermaid diagrams.
--]]

function string:endswith(ending)
    return ending == "" or self:sub(-#ending) == ending
end

function string:startswith(start)
   return self:sub(1, #start) == start
end

function loadContent(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end


function Image(el)
  local old = el.src
  if FORMAT:match "html5" then
    -- remove references to the content folder
    if el.src:startswith "content/"  then
      el.src = el.src:gsub("content/","")
    end
    -- if the image is an SVG, inline it because clickevents only work if it is an inline SVG.
    if el.src:endswith ".svg" then
      if io.open(old, "rb") ~= nil then
        local svg = loadContent(old)
        return pandoc.RawInline("html5", svg)
      end
    end
  end

  return el
end
