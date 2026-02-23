new Vue({
    el: '#app',
    data() {
        return {
            activeTab: 'preview',
            // 用户
            user: null,
            // 音乐
            audio: null,
            // 商品列表
            goodsList: [],
            // 传入的多个 goods 数据数组
            previewList: [],
            // 预览窗口是否可见
            previewVisible: false,
            // 当前预览的 item 数据
            previewData: {},
            // 最大值
            maxCount: 0,

            visible: false,
            text: '',
            type: 'info',
            timer: null,
            left: '74px',
            top: '556px'
        }
    },

    created() {

    },

    mounted() {

    },

    methods: {

    }
})