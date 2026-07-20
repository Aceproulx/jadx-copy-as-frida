package frida.copy;

import jadx.api.JadxDecompiler;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.api.metadata.ICodeAnnotation;
import jadx.api.metadata.ICodeNodeRef;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.MethodNode;
import java.util.List;
import java.util.stream.Collectors;

public class FridaCopyPlugin implements JadxPlugin {

    private static final String ID = "frida-copy";

    @Override
    public JadxPluginInfo getPluginInfo() {
        return JadxPluginInfoBuilder.pluginId(ID)
                .name("Frida Script Copier")
                .description("Right-click any method to copy Frida hook scripts to clipboard")
                .build();
    }

    @Override
    public void init(JadxPluginContext ctx) {
        JadxGuiContext gui = ctx.getGuiContext();
        JadxDecompiler decompiler = ctx.getDecompiler();

        register(gui, decompiler, "Frida: Hook & log args/ret", ScriptType.LOG);
        register(gui, decompiler, "Frida: Return true", ScriptType.RETURN_TRUE);
        register(gui, decompiler, "Frida: Return false", ScriptType.RETURN_FALSE);
        register(gui, decompiler, "Frida: Trace call + stack", ScriptType.TRACE);
        register(gui, decompiler, "Frida: Hook all overloads", ScriptType.OVERLOADS);
    }

    private void register(JadxGuiContext gui, JadxDecompiler decompiler, String label, ScriptType type) {
        gui.addPopupMenuAction(
                label,
                ref -> isMethod(ref, decompiler),
                null,
                ref -> {
                    JavaNode node = decompiler.getJavaNodeByRef(ref);
                    if (node instanceof JavaMethod) {
                        gui.copyToClipboard(buildScript((JavaMethod) node, type));
                    }
                }
        );
    }

    private boolean isMethod(ICodeNodeRef ref, JadxDecompiler decompiler) {
        if (ref.getAnnType() != ICodeAnnotation.AnnType.METHOD) return false;
        JavaNode node = decompiler.getJavaNodeByRef(ref);
        return node instanceof JavaMethod;
    }

    private boolean isOverloaded(JavaMethod mth) {
        MethodNode mthNode = mth.getMethodNode();
        if (mthNode == null) return false;
        ClassNode cls = mthNode.getDeclaringClass();
        if (cls == null) return false;
        MethodInfo info = mthNode.getMethodInfo();
        for (MethodNode other : cls.getMethods()) {
            if (other.getMethodInfo() != info && other.getMethodInfo().isOverloadedBy(info)) {
                return true;
            }
        }
        return false;
    }

    // ---- Script generation ----

    private String buildScript(JavaMethod mth, ScriptType type) {
        String cls = mth.getDeclaringClass().getFullName();
        String name = mth.getName();
        List<String> argTypes = mth.getArguments().stream()
                .map(t -> toFridaType(t.toString()))
                .collect(Collectors.toList());

        if (type == ScriptType.OVERLOADS || isOverloaded(mth)) {
            return buildOverloaded(cls, name, type);
        }

        String decl = buildParamDecl(argTypes);
        String call = buildArgList(argTypes.size());

        switch (type) {
            case LOG: return genLog(cls, name, decl, call, argTypes);
            case RETURN_TRUE: return genReturn(cls, name, decl, "true");
            case RETURN_FALSE: return genReturn(cls, name, decl, "false");
            case TRACE: return genTrace(cls, name, decl, call);
            default: return "";
        }
    }

    // ---- Single-overload scripts ----

    private String genLog(String cls, String name, String decl, String call, List<String> argTypes) {
        StringBuilder logParts = new StringBuilder();
        for (int i = 0; i < argTypes.size(); i++) {
            if (i > 0) logParts.append(" + \", \" + ");
            logParts.append("\"").append(argTypes.get(i)).append(i).append("=\" + ").append(argTypes.get(i)).append(i);
        }
        String logExpr = logParts.length() > 0 ? logParts.toString() : "\"\"";

        return String.format(
            "Java.perform(function() {\n" +
            "  var %s = Java.use(\"%s\");\n" +
            "  %s.%s.implementation = function(%s) {\n" +
            "    console.log(\"[frida-copy] %s.%s(\" + %s + \")\");\n" +
            "    var ret = this.%s(%s);\n" +
            "    console.log(\"[frida-copy] %s.%s => \" + ret);\n" +
            "    return ret;\n" +
            "  };\n" +
            "  console.log(\"[frida-copy] Hooked %s.%s\");\n" +
            "});\n",
            var(cls), cls,
            var(cls), name, decl,
            cls, name, logExpr,
            name, call,
            cls, name,
            cls, name
        );
    }

    private String genReturn(String cls, String name, String decl, String retVal) {
        return String.format(
            "Java.perform(function() {\n" +
            "  var %s = Java.use(\"%s\");\n" +
            "  %s.%s.implementation = function(%s) {\n" +
            "    console.log(\"[frida-copy] %s.%s => %s bypass\");\n" +
            "    return %s;\n" +
            "  };\n" +
            "  console.log(\"[frida-copy] %s.%s => %s bypass\");\n" +
            "});\n",
            var(cls), cls,
            var(cls), name, decl,
            cls, name, retVal,
            retVal,
            cls, name, retVal
        );
    }

    private String genTrace(String cls, String name, String decl, String call) {
        return String.format(
            "Java.perform(function() {\n" +
            "  var %s = Java.use(\"%s\");\n" +
            "  %s.%s.implementation = function(%s) {\n" +
            "    console.log(\"[frida-copy] %s.%s()\");\n" +
            "    console.log(Java.use(\"android.util.Log\").getStackTraceString(\n" +
            "      Java.use(\"java.lang.Throwable\").$new()));\n" +
            "    return this.%s(%s);\n" +
            "  };\n" +
            "  console.log(\"[frida-copy] Traced %s.%s\");\n" +
            "});\n",
            var(cls), cls,
            var(cls), name, decl,
            cls, name,
            name, call,
            cls, name
        );
    }

    // ---- Overloaded scripts ----

    private String buildOverloaded(String cls, String name, ScriptType type) {
        switch (type) {
            case LOG:
                return String.format(
                    "Java.perform(function() {\n" +
                    "  var %s = Java.use(\"%s\");\n" +
                    "  %s.%s.overloads.forEach(function(overload) {\n" +
                    "    overload.implementation = function() {\n" +
                    "      var args = Array.prototype.slice.call(arguments);\n" +
                    "      console.log(\"[frida-copy] %s.%s(\" + JSON.stringify(args) + \")\");\n" +
                    "      var ret = overload.apply(this, arguments);\n" +
                    "      console.log(\"[frida-copy] %s.%s => \" + ret);\n" +
                    "      return ret;\n" +
                    "    };\n" +
                    "  });\n" +
                    "  console.log(\"[frida-copy] Hooked %s.%s (all overloads)\");\n" +
                    "});\n",
                    var(cls), cls,
                    var(cls), name,
                    cls, name,
                    cls, name,
                    cls, name
                );
            case RETURN_TRUE:
                return overloadedReturn(cls, name, "true");
            case RETURN_FALSE:
                return overloadedReturn(cls, name, "false");
            case TRACE:
                return String.format(
                    "Java.perform(function() {\n" +
                    "  var %s = Java.use(\"%s\");\n" +
                    "  %s.%s.overloads.forEach(function(overload) {\n" +
                    "    overload.implementation = function() {\n" +
                    "      console.log(\"[frida-copy] %s.%s() (overloaded)\");\n" +
                    "      console.log(Java.use(\"android.util.Log\").getStackTraceString(\n" +
                    "        Java.use(\"java.lang.Throwable\").$new()));\n" +
                    "      return overload.apply(this, arguments);\n" +
                    "    };\n" +
                    "  });\n" +
                    "  console.log(\"[frida-copy] Traced %s.%s (all overloads)\");\n" +
                    "});\n",
                    var(cls), cls,
                    var(cls), name,
                    cls, name,
                    cls, name
                );
            default:
                return "";
        }
    }

    private String overloadedReturn(String cls, String name, String retVal) {
        return String.format(
            "Java.perform(function() {\n" +
            "  var %s = Java.use(\"%s\");\n" +
            "  %s.%s.overloads.forEach(function(overload) {\n" +
            "    overload.implementation = function() {\n" +
            "      console.log(\"[frida-copy] %s.%s => %s bypass (overloaded)\");\n" +
            "      return %s;\n" +
            "    };\n" +
            "  });\n" +
            "  console.log(\"[frida-copy] %s.%s => %s bypass (all overloads)\");\n" +
            "});\n",
            var(cls), cls,
            var(cls), name,
            cls, name, retVal,
            retVal,
            cls, name, retVal
        );
    }

    // ---- Helpers ----

    private static String buildParamDecl(List<String> argTypes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < argTypes.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(argTypes.get(i)).append(i);
        }
        return sb.toString();
    }

    private static String buildArgList(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(", ");
            sb.append("_").append(i);
        }
        return sb.toString();
    }

    private static String var(String fullName) {
        int dot = fullName.lastIndexOf('.');
        String s = dot >= 0 ? fullName.substring(dot + 1) : fullName;
        return s.replace("$", "_");
    }

    private static String toFridaType(String type) {
        if (type == null || type.isEmpty()) return "arg";
        switch (type) {
            case "boolean": return "b";
            case "byte":    return "by";
            case "char":    return "c";
            case "short":   return "sh";
            case "int":     return "i";
            case "long":    return "l";
            case "float":   return "f";
            case "double":  return "d";
            default:
                if (type.startsWith("[")) return "arr";
                int lastDot = type.lastIndexOf('.');
                return lastDot >= 0 ? type.substring(lastDot + 1).toLowerCase() : "obj";
        }
    }

    private enum ScriptType {
        LOG, RETURN_TRUE, RETURN_FALSE, TRACE, OVERLOADS
    }
}
