export function hasSeleniumProperties() {
    const seleniumProps = [
        "__driver_evaluate",
        "__webdriver_evaluate", 
        "__selenium_evaluate",
        "__fxdriver_evaluate",
        "__driver_unwrapped",
        "__webdriver_unwrapped",
        "__selenium_unwrapped", 
        "__fxdriver_unwrapped",
        "_Selenium_IDE_Recorder",
        "_selenium",
        "calledSelenium",
        "$cdc_asdjflasutopfhvcZLmcfl_",
        "$chrome_asyncScriptInfo",
        "__$webdriverAsyncExecutor",
        "webdriver",
        "__webdriverFunc",
        "domAutomation",
        "domAutomationController",
        "__lastWatirAlert",
        "__lastWatirConfirm",
        "__lastWatirPrompt",
        "__webdriver_script_fn",
        "_WEBDRIVER_ELEM_CACHE"
      ];

      let hasSeleniumProperty = false;

      for (let i = 0; i < seleniumProps.length; i++) {
        if (seleniumProps[i] in window) {
          hasSeleniumProperty = true;
          break;
        }
      }

      hasSeleniumProperty = hasSeleniumProperty || !!(document as any).__webdriver_script_fn || !!(window as any).domAutomation || !!(window as any).domAutomationController
      
      return hasSeleniumProperty;
}