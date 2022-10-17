--[[ 
This is a Pandoc filter to execute inline Lua codeblocks in Markdown files.

This only executes if the Markdown file has "dynamic" set to true in its metatada
--]]

local dynamic = false

function Meta(m)
  dynamic = m["dynamic"]

  return m
end

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end



function CodeBlock(el)
  if FORMAT:match "html5" then
    if el.classes[1] == "lua" and dynamic then
      f = load(el.text)
      return pandoc.RawBlock("html5", f())
    end
  end

  return el
end


return {
  { Meta = Meta },
  { CodeBlock = CodeBlock}
}