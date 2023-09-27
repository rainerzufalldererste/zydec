ProjectName = "zydec"
project(ProjectName)

  --Settings
  kind "StaticLib"
  language "C++"
  staticruntime "On"

  filter { "system:windows" }
    buildoptions { '/Gm-' }
    buildoptions { '/MP' }

    ignoredefaultlibraries { "msvcrt" }
  filter { "system:linux" }
    cppdialect "C++11"
  filter { }
  
  defines { "_CRT_SECURE_NO_WARNINGS", "SSE2" }
  
  objdir "intermediate/obj"

  files { "src/**.cpp", "src/**.c", "src/**.cc", "src/**.h", "src/**.hh", "src/**.hpp", "src/**.inl", "src/**rc" }
  files { "include/**.h", "include/**.hh", "include/**.hpp", "include/**.inl" }
  files { "project.lua" }
  
  includedirs { "include", "include/**" }
  includedirs { "../3rdParty/Zydis/include" }

  filter { "configurations:Debug", "system:Windows" }
    ignoredefaultlibraries { "libcmt" }
  filter { }
  
  targetname(ProjectName)
  targetdir "../builds/lib"
  debugdir "../builds/lib"
  
filter {}
configuration {}

warnings "Extra"

filter {}
configuration {}
flags { "NoMinimalRebuild", "NoPCH" }
exceptionhandling "Off"
rtti "Off"
floatingpoint "Fast"

filter { "configurations:Debug*" }
	defines { "_DEBUG" }
	optimize "Off"
	symbols "On"

filter { "configurations:Release" }
	defines { "NDEBUG" }
	optimize "Speed"
	flags { "NoBufferSecurityCheck", "NoIncrementalLink" }
  omitframepointer "On"
	symbols "On"

filter { "system:windows", "configurations:Release", "action:vs2012" }
	buildoptions { "/d2Zi+" }

filter { "system:windows", "configurations:Release", "action:vs2013" }
	buildoptions { "/Zo" }

filter { "system:windows", "configurations:Release" }
	flags { "NoIncrementalLink" }

editandcontinue "Off"
