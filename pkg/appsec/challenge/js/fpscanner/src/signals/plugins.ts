import { SignalValue } from "../types";
import { INIT, NA, hashCode, ERROR, setObjectValues} from "./utils";

function isValidPluginArray() {
    if (!navigator.plugins) return false;
    const str = typeof navigator.plugins.toString === "function" 
      ? navigator.plugins.toString() 
      : navigator.plugins.constructor && typeof navigator.plugins.constructor.toString === "function"
        ? navigator.plugins.constructor.toString()
        : typeof navigator.plugins;
    return str === "[object PluginArray]" || 
           str === "[object MSPluginsCollection]" || 
           str === "[object HTMLPluginsCollection]";
  }

  function getPluginNamesHash() {
    if (!navigator.plugins) return NA;

    const pluginNames = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      pluginNames.push(navigator.plugins[i].name);
    }
    return hashCode(pluginNames.join(","));
  }


  function getPluginCount() {
    if (!navigator.plugins) return NA;
    return navigator.plugins.length;
  }

  function getPluginConsistency1() {
    if (!navigator.plugins) return NA;
    try {
        return navigator.plugins[0] === navigator.plugins[0][0].enabledPlugin;
    } catch (e) {
        return ERROR;
    }
  }

  function getPluginOverflow() {
    if (!navigator.plugins) return NA;

    try {
        return navigator.plugins.item(4294967296) !== navigator.plugins[0];
    } catch (e) {
        return ERROR;
    }
  }

export function plugins() {
    const pluginsData = {
        isValidPluginArray: INIT as SignalValue<boolean>,
        pluginCount: INIT as SignalValue<number>,
        pluginNamesHash: INIT as SignalValue<string>,
        pluginConsistency1: INIT as SignalValue<boolean>,
        pluginOverflow: INIT as SignalValue<boolean>,
    }
    
    try {
        pluginsData.isValidPluginArray = isValidPluginArray();
        pluginsData.pluginCount = getPluginCount();
        pluginsData.pluginNamesHash = getPluginNamesHash();
        pluginsData.pluginConsistency1 = getPluginConsistency1();
        pluginsData.pluginOverflow = getPluginOverflow();
    } catch (e) {
        setObjectValues(pluginsData, ERROR);
    }
    return pluginsData;
}