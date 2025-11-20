/**
 * Event Listener Debugging Utility
 *
 * This utility helps inspect user interactions and typing events for debugging.
 * It can track clicks, key presses, form inputs, and more.
 *
 * Usage:
 *   import { EventDebugger } from '@/utils/eventDebugger';
 *
 *   // Enable debugging
 *   EventDebugger.enable();
 *
 *   // Check console for event logs
 *   // Or access EventDebugger.getHistory() programmatically
 */

class EventDebuggerClass {
  constructor() {
    this.enabled = false;
    this.history = [];
    this.maxHistorySize = 1000;
    this.listeners = [];
    this.ignoredElements = new Set(['html', 'body']);
  }

  /**
   * Enable event debugging
   */
  enable() {
    if (this.enabled) {
      console.warn('EventDebugger is already enabled');
      return;
    }

    this.enabled = true;
    this.attachListeners();
    console.log('%c[EventDebugger] Enabled', 'color: #22c55e; font-weight: bold');
    console.log('%cType EventDebugger.getHistory() to see all captured events', 'color: #3b82f6');
    console.log('%cType EventDebugger.clearHistory() to clear event history', 'color: #3b82f6');
    console.log('%cType EventDebugger.disable() to stop debugging', 'color: #3b82f6');
  }

  /**
   * Disable event debugging
   */
  disable() {
    if (!this.enabled) return;

    this.enabled = false;
    this.removeListeners();
    console.log('%c[EventDebugger] Disabled', 'color: #ef4444; font-weight: bold');
  }

  /**
   * Attach event listeners to document
   */
  attachListeners() {
    // Click events
    const clickHandler = (e) => this.logEvent('click', e);
    document.addEventListener('click', clickHandler, true);
    this.listeners.push({ type: 'click', handler: clickHandler });

    // Double click events
    const dblclickHandler = (e) => this.logEvent('dblclick', e);
    document.addEventListener('dblclick', dblclickHandler, true);
    this.listeners.push({ type: 'dblclick', handler: dblclickHandler });

    // Keyboard events
    const keydownHandler = (e) => this.logKeyboardEvent('keydown', e);
    document.addEventListener('keydown', keydownHandler, true);
    this.listeners.push({ type: 'keydown', handler: keydownHandler });

    const keyupHandler = (e) => this.logKeyboardEvent('keyup', e);
    document.addEventListener('keyup', keyupHandler, true);
    this.listeners.push({ type: 'keyup', handler: keyupHandler });

    // Input events (tracks typing in form fields)
    const inputHandler = (e) => this.logInputEvent('input', e);
    document.addEventListener('input', inputHandler, true);
    this.listeners.push({ type: 'input', handler: inputHandler });

    // Change events
    const changeHandler = (e) => this.logInputEvent('change', e);
    document.addEventListener('change', changeHandler, true);
    this.listeners.push({ type: 'change', handler: changeHandler });

    // Focus events
    const focusHandler = (e) => this.logEvent('focus', e);
    document.addEventListener('focus', focusHandler, true);
    this.listeners.push({ type: 'focus', handler: focusHandler });

    // Blur events
    const blurHandler = (e) => this.logEvent('blur', e);
    document.addEventListener('blur', blurHandler, true);
    this.listeners.push({ type: 'blur', handler: blurHandler });

    // Mouse events
    const mouseenterHandler = (e) => this.logEvent('mouseenter', e);
    document.addEventListener('mouseenter', mouseenterHandler, true);
    this.listeners.push({ type: 'mouseenter', handler: mouseenterHandler });

    // Submit events
    const submitHandler = (e) => this.logEvent('submit', e);
    document.addEventListener('submit', submitHandler, true);
    this.listeners.push({ type: 'submit', handler: submitHandler });

    // Scroll events
    const scrollHandler = (e) => this.logEvent('scroll', e);
    document.addEventListener('scroll', scrollHandler, true);
    this.listeners.push({ type: 'scroll', handler: scrollHandler });
  }

  /**
   * Remove all event listeners
   */
  removeListeners() {
    this.listeners.forEach(({ type, handler }) => {
      document.removeEventListener(type, handler, true);
    });
    this.listeners = [];
  }

  /**
   * Log a standard event
   */
  logEvent(eventType, event) {
    if (!this.enabled) return;

    const target = event.target;
    if (this.ignoredElements.has(target.tagName?.toLowerCase())) return;

    const eventData = {
      type: eventType,
      timestamp: new Date().toISOString(),
      target: this.getElementInfo(target),
      details: this.getEventDetails(event)
    };

    this.addToHistory(eventData);
    this.consoleLog(eventData);
  }

  /**
   * Log keyboard event with key information
   */
  logKeyboardEvent(eventType, event) {
    if (!this.enabled) return;

    const target = event.target;
    const eventData = {
      type: eventType,
      timestamp: new Date().toISOString(),
      target: this.getElementInfo(target),
      key: event.key,
      code: event.code,
      keyCode: event.keyCode,
      altKey: event.altKey,
      ctrlKey: event.ctrlKey,
      shiftKey: event.shiftKey,
      metaKey: event.metaKey,
      details: this.getEventDetails(event)
    };

    this.addToHistory(eventData);
    this.consoleLog(eventData, event.key);
  }

  /**
   * Log input event with current value
   */
  logInputEvent(eventType, event) {
    if (!this.enabled) return;

    const target = event.target;
    if (target.tagName?.toLowerCase() === 'input' ||
        target.tagName?.toLowerCase() === 'textarea' ||
        target.tagName?.toLowerCase() === 'select') {

      const eventData = {
        type: eventType,
        timestamp: new Date().toISOString(),
        target: this.getElementInfo(target),
        value: target.value,
        inputType: event.inputType,
        details: this.getEventDetails(event)
      };

      this.addToHistory(eventData);
      this.consoleLog(eventData, target.value);
    }
  }

  /**
   * Get element information
   */
  getElementInfo(element) {
    if (!element) return null;

    return {
      tagName: element.tagName?.toLowerCase(),
      id: element.id || null,
      className: element.className || null,
      name: element.name || null,
      type: element.type || null,
      text: element.textContent?.substring(0, 50) || null,
      selector: this.getSelector(element)
    };
  }

  /**
   * Generate CSS selector for element
   */
  getSelector(element) {
    if (!element) return '';
    if (element.id) return `#${element.id}`;

    let selector = element.tagName?.toLowerCase() || '';
    if (element.className) {
      const classes = element.className.split(' ').filter(c => c);
      if (classes.length > 0) {
        selector += '.' + classes.join('.');
      }
    }

    return selector || element.tagName?.toLowerCase();
  }

  /**
   * Get additional event details
   */
  getEventDetails(event) {
    return {
      bubbles: event.bubbles,
      cancelable: event.cancelable,
      defaultPrevented: event.defaultPrevented,
      isTrusted: event.isTrusted
    };
  }

  /**
   * Add event to history
   */
  addToHistory(eventData) {
    this.history.push(eventData);

    // Limit history size
    if (this.history.length > this.maxHistorySize) {
      this.history.shift();
    }
  }

  /**
   * Console log event with formatting
   */
  consoleLog(eventData, extra = null) {
    const color = this.getEventColor(eventData.type);
    const extraInfo = extra ? ` | ${extra}` : '';

    console.log(
      `%c[${eventData.type.toUpperCase()}]%c ${eventData.target?.selector || 'unknown'}${extraInfo}`,
      `color: ${color}; font-weight: bold`,
      'color: #6b7280',
      eventData
    );
  }

  /**
   * Get color for event type
   */
  getEventColor(type) {
    const colors = {
      click: '#3b82f6',
      dblclick: '#8b5cf6',
      keydown: '#10b981',
      keyup: '#059669',
      input: '#f59e0b',
      change: '#f97316',
      focus: '#06b6d4',
      blur: '#64748b',
      submit: '#ec4899',
      scroll: '#84cc16',
      mouseenter: '#6366f1'
    };
    return colors[type] || '#6b7280';
  }

  /**
   * Get event history
   */
  getHistory() {
    return this.history;
  }

  /**
   * Get filtered history by event type
   */
  getHistoryByType(type) {
    return this.history.filter(event => event.type === type);
  }

  /**
   * Get recent events
   */
  getRecentEvents(count = 10) {
    return this.history.slice(-count);
  }

  /**
   * Clear history
   */
  clearHistory() {
    this.history = [];
    console.log('%c[EventDebugger] History cleared', 'color: #3b82f6');
  }

  /**
   * Export history as JSON
   */
  exportHistory() {
    const json = JSON.stringify(this.history, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `event-history-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    console.log('%c[EventDebugger] History exported', 'color: #22c55e');
  }

  /**
   * Get statistics
   */
  getStats() {
    const stats = {};
    this.history.forEach(event => {
      stats[event.type] = (stats[event.type] || 0) + 1;
    });

    console.table(stats);
    return stats;
  }
}

// Create singleton instance
export const EventDebugger = new EventDebuggerClass();

// Make it available globally for console access
if (typeof window !== 'undefined') {
  window.EventDebugger = EventDebugger;
}

export default EventDebugger;
