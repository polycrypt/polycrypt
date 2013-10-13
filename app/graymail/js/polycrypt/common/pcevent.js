function PCEvent(type) {
    this.init(type);
}

PCEvent.prototype = {
    // Constants
    CAPTURING_PHASE: 1,
    AT_TARGET: 2,
    BUBBLING_PHASE: 3,

    // Fields
    type: null, 
    target: null,
    currentTarget: null,
    eventPhase: this.AT_TARGET,
    bubbles: false,
    cancelable: false,


    // Methods
    init: function Event_init(type) {
        this.type = type;
    },

    // Required by the spec, but NOOP for us
    stopPropagation: function Event_stopPropagation() {
    },
    
    // Required by the spec, but NOOP for us
    preventDefault: function Event_stopPropagation() {
    },
};
